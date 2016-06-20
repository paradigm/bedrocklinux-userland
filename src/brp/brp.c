/*
 * brp.c
 *
 *      This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      version 2 as published by the Free Software Foundation.
 *
 * Copyright (c) 2014-2015 Daniel Thau <danthau@bedrocklinux.org>
 *
 * This program mounts a filesystem which will provide read-only copies of
 * files at configured output locations dependent on various possible input
 * locations.  For example, if "<mount>/bin/vlc" is requested, this program can
 * search through a configured list of possible locations for "vlc" and provide
 * the first match, if any.
 */

#define FUSE_USE_VERSION 29
#include <fuse.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <libbedrock.h>

#define CONFIG "/bedrock/etc/brp.conf"
#define CONFIG_LEN strlen(CONFIG)
#define STRATA_ROOT "/bedrock/strata/"
#define STRATA_ROOT_LEN strlen(STRATA_ROOT)

#define MIN(x, y) (x < y ? x : y)

enum filter {
	FILTER_PASS,     /* pass file through unaltered */
	FILTER_BRC_WRAP, /* return a script that wraps executable with brc */
	FILTER_EXEC,     /* wrap [Try]Exec[Start|Stop|Reload]= ini-style key-value pairs with brc */
// 	FILTER_FONT,     /* combines fonts.dir and fonts.alias files for Xorg fonts */
};

enum file_type {
	FILE_TYPE_NORMAL,
	FILE_TYPE_DIRECTORY,
};

/*
 * Possible input source for a file.
 */
struct in_item {
	/* stratum-specific component of path, e.g. "/bin/ls" */
	char *path;
	size_t path_len;

	/* if this in_item has a stratum specification, it's
	 * stored here, otherwise this is -1 */
	int stratum_id;
};

/*
 * Possible output file or directory, if a matching in_item is found.
 */
struct out_item {
	/* incoming path stratum may request for file, e.g. <mount-point>"/bin/ls" */
	char *path;
	size_t path_len;
	/* what kind of filter to apply to outgoing files */
	int filter;
	/* is this a directory that can contain multiple files, or just a single file */
	int file_type;
	/* array of possible in_items for the output item */
	struct in_item *in_items;
	size_t in_item_count;
};

static char **stratum;
static size_t *stratum_len;
static int nstratum;

#include "parser.h"

#define CONFIG "/bedrock/etc/brp.conf"
#define CONFIG_LEN strlen(CONFIG)
#define STRATA_ROOT "/bedrock/strata/"
#define STRATA_ROOT_LEN strlen(STRATA_ROOT)

#define MIN(x, y) (x < y ? x : y)
#define unlikely(x)                                                            \
	(__builtin_constant_p(x) ? !!(x) : __builtin_expect(!!(x), 0))

/*
 * The functions corresponding to the various filesystem calls have
 * FUSE-defined arguments which are not easily changed.  Easiest/cleanest way to pass
 * additional information to each function is via globals.
 */

/* output file paths */
struct out_item *out_items;
size_t out_item_count = 0;

/* default stat information so we don't have to recalculate at runtime. */
struct stat parent_stat;
struct stat reparse_stat;

/*
 * ============================================================================
 * config management
 * ============================================================================
 */

void free_config()
{
	if (out_item_count <= 0) {
		return;
	}

	size_t i, j;
	for (i = 0; i < out_item_count; i++) {
		for (j = 0; j < out_items[i].in_item_count; j++)
			free(out_items[i].in_items[j].path);
		free(out_items[i].in_items);
		free(out_items[i].path);
	}
	free(out_items);
	free(stratum);
	free(stratum_len);
	nstratum = 0;
	out_item_count = 0;
}

static inline void _add_stratum(char ***stratum_p, size_t *arrsz,
				const char *new_stratum)
{
	size_t s = 0;
	while ((*stratum_p)[s] != NULL) {
		if (strcmp((*stratum_p)[s], new_stratum) == 0)
			return;
		s++;
	}

	if (s >= *arrsz - 1) {
		*arrsz *= 2;
		*stratum_p = realloc(*stratum_p, *arrsz * sizeof(void *));
	}
	(*stratum_p)[s] = strdup(new_stratum);
	(*stratum_p)[s + 1] = NULL;
}

void brp_parse_config()
{
	/*
	 * Free memory associated with previous config parsing
	 */
	free_config();

	/*
	 * Ensure we're using a root-modifiable-only configuration file, just in
	 * case.
	 */
	if (!check_config_secure(CONFIG)) {
		fprintf(stderr, "brp: config file at " CONFIG
				" is not secure, refusing to continue.\n");
		exit(1);
	}

	int nsec;
	struct section *sec = parse_config(CONFIG, &nsec), *sec_curr = sec;

	if (sec == NULL)
		exit(1);

	size_t arrsz = 0;
	while (sec_curr) {
		if (strcmp(sec_curr->name, "stratum-order"))
			out_item_count += sec_curr->nent;
		else {
			arrsz = sec_curr->nent + 1;
			stratum = calloc(sec_curr->nent + 1, sizeof(void *));

			struct entry *e = sec_curr->e;
			while (e) {
				_add_stratum(&stratum, &arrsz, e->lhs);
				e = e->next;
			}
		}
		sec_curr = sec_curr->next;
	}

	struct dirent *dent;
	DIR *d = opendir("/bedrock/run/enabled_strata/");
	if (!d) {
		perror("Failed to list enabled strata");
		exit(1);
	}

	if (!arrsz) {
		arrsz = 1;
		stratum = calloc(1, sizeof(void *));
	}
	while ((dent = readdir(d)))
		if (strncmp(dent->d_name, ".", 1) &&
		    strncmp(dent->d_name, "..", 2))
			_add_stratum(&stratum, &arrsz, dent->d_name);

	closedir(d);

	char **tmp_s = stratum;
	nstratum = 0;
	while (*tmp_s) {
		nstratum++;
		tmp_s++;
	}

	stratum_len = malloc(sizeof(size_t) * nstratum);

	for (int st = 0; st < nstratum; st++)
		stratum_len[st] = strlen(stratum[st]);

	out_items = malloc(out_item_count * sizeof(struct out_item));
	sec_curr = sec;

	int i = 0;
	int curr_filter = 0;
	while (sec_curr) {
		struct entry *e = sec_curr->e;
		if (strcmp(sec_curr->name, "pass") == 0) {
			curr_filter = FILTER_PASS;
		} else if (strcmp(sec_curr->name, "brc-wrap") == 0) {
			curr_filter = FILTER_BRC_WRAP;
		} else if (strcmp(sec_curr->name, "exec-filter") == 0) {
			curr_filter = FILTER_EXEC;
		} else if (strcmp(sec_curr->name, "stratum-order") == 0) {
			sec_curr = sec_curr->next;
			continue;
		} else {
			fprintf(stderr, "brp: Failed to parse config\n");
			exit(1);
		}
		while (e) {
			/* get path */
			out_items[i].path = strdup(e->lhs);
			out_items[i].path_len = e->lhs_len;

			if (out_items[i].path[out_items[i].path_len - 1] ==
			    '/') {
				out_items[i].file_type = FILE_TYPE_DIRECTORY;
				out_items[i].path[--out_items[i].path_len] =
				    '\0';
			} else
				out_items[i].file_type = FILE_TYPE_NORMAL;

			out_items[i].filter = curr_filter;

			out_items[i].in_items =
			    malloc(e->nrhs * sizeof(struct in_item));

			struct rhs *r = e->r;
			struct in_item *in_items = out_items[i].in_items;
			int j = 0;
			while (r) {
				in_items[j].stratum_id = -1;
				if (r->str[0] != '/') {
					// The in_path might start with a
					// stratum
					// specification
					char *colon = strchr(r->str, ':');
					if (!colon || colon[1] != '/') {
						// Invalid path, just ignore
						r = r->next;
						continue;
					}
					in_items[j].path = strdup(colon + 1);
					for (int st = 0; st < nstratum; st++)
						if (strncmp(r->str, stratum[st],
							    colon - r->str) ==
						    0) {
							in_items[j].stratum_id =
							    st;
							break;
						}
					if (in_items[j].stratum_id == -1) {
						r = r->next;
						continue;
					}
				} else
					in_items[j].path = strdup(r->str);
				in_items[j].path_len = strlen(in_items[j].path);
				j++;

				r = r->next;
			}
			out_items[i].in_item_count = j;
			i++;
			e = e->next;
		}
		sec_curr = sec_curr->next;
	}

	free_sections(sec);
}

/*
 * Return a pointer to a string describing the current configuration.  Up to
 * the calling program to free() it.  This is used when /reparse_config is read
 * to show the current configuration.  It is useful for debugging.
 */
char *config_contents()
{
	size_t len = 0;
	for (size_t i = 0; i < out_item_count; i++) {
		len += strlen("path = ");
		len += strlen(out_items[i].path);
		len += strlen("\n");

		len += strlen("type = ");
		switch (out_items[i].file_type) {
		case FILE_TYPE_NORMAL:
			len += strlen("normal");
			break;
		case FILE_TYPE_DIRECTORY:
			len += strlen("directory");
			break;
		}
		len += strlen("\n");

		len += strlen("filter = ");
		switch (out_items[i].filter) {
		case FILTER_PASS:
			len += strlen("pass");
			break;
		case FILTER_BRC_WRAP:
			len += strlen("brc-wrap");
			break;
		case FILTER_EXEC:
			len += strlen("exec");
			break;
		}
		len += strlen("\n");

		for (size_t j = 0; j < out_items[i].in_item_count; j++) {
			for (int st = 0; st < nstratum; st++) {
				len += strlen("  stratum = ");
				len += strlen(stratum[st]);
				len += strlen("\n");
				len += strlen("  stratum_path = ");
				len += strlen(stratum[st]) + STRATA_ROOT_LEN;
				len += strlen("\n");
				len += strlen("  full_path = ");
				len += strlen(stratum[st]) +
				       out_items[i].in_items[j].path_len +
				       STRATA_ROOT_LEN;
				len += strlen("\n");
			}
		}
	}
	len += strlen("\n");

	char *config_str = malloc((len + 1) * sizeof(char));
	if (!config_str) {
		return NULL;
	}
	config_str[0] = '\0';

	for (size_t i = 0; i < out_item_count; i++) {
		strcat(config_str, "path = ");
		strcat(config_str, out_items[i].path);
		strcat(config_str, "\n");

		strcat(config_str, "type = ");
		switch (out_items[i].file_type) {
		case FILE_TYPE_NORMAL:
			strcat(config_str, "normal");
			break;
		case FILE_TYPE_DIRECTORY:
			strcat(config_str, "directory");
			break;
		}
		strcat(config_str, "\n");

		strcat(config_str, "filter = ");
		switch (out_items[i].filter) {
		case FILTER_PASS:
			strcat(config_str, "pass");
			break;
		case FILTER_BRC_WRAP:
			strcat(config_str, "brc-wrap");
			break;
		case FILTER_EXEC:
			strcat(config_str, "exec");
			break;
		}
		strcat(config_str, "\n");

		for (size_t j = 0; j < out_items[i].in_item_count; j++) {
			for (int st = 0; st < nstratum; st++) {
				strcat(config_str, "  stratum = ");
				strcat(config_str, stratum[st]);
				strcat(config_str, "\n");
				strcat(config_str, "  stratum_path = ");
				strcat(config_str, STRATA_ROOT);
				strcat(config_str, stratum[st]);
				strcat(config_str, "\n");
				strcat(config_str, "  full_path = ");
				strcat(config_str, STRATA_ROOT);
				strcat(config_str, stratum[st]);
				strcat(config_str, out_items[i].in_items[j].path);
				strcat(config_str, "\n");
			}
		}
	}

	return config_str;
}

/*
 * ============================================================================
 * str_vec
 * ============================================================================
 *
 * Growable array of strings.
 */

struct str_vec {
	char** array;
	size_t len;
	size_t allocated;
};

int str_vec_new(struct str_vec *v)
{
	const int DEFAULT_ALLOC_SIZE = 1024;
	v->allocated = DEFAULT_ALLOC_SIZE;
	v->len = 0;
	v->array = malloc(v->allocated * sizeof(char*));
	return !!v->array;
}

void str_vec_free(struct str_vec *v)
{
	size_t i;
	for (i = 0; i < v->len; i++) {
		free(v->array[i]);
	}
	free(v->array);
	v->array = NULL;
	v->len = 0;
	v->allocated = 0;
	/*
	 * Purposefully cannot append anymore (0 * 2 = 0).  have to call
	 * str_vec_new() again to continue to use.
	 */
}

int str_vec_append(struct str_vec *v, char *str)
{
	/* cannot append on free()'d str_vec */
	if (v->allocated == 0) {
		return 0;
	}

	size_t str_len = strlen(str);
	v->array[v->len] = malloc((str_len+1) * sizeof(char));
	if (!v->array[v->len]) {
		return 0;
	}
	strcpy(v->array[v->len], str);

	v->len++;
	if (v->len > v->allocated) {
		v->allocated *= 2; /* TODO: research scaling 1.5 vs 2 */
		v->array = realloc(v->array, v->allocated * sizeof(char*));
		if (!v->array) {
			return 0;
		}
	}
	return 1;
}

int str_vec_concat(struct str_vec *v1, struct str_vec *v2)
{
	size_t i;
	for (i = 0; i < v2->len; i++) {
		if (str_vec_append(v1, v2->array[i]) < 0) {
			return 0;
		}
	}
	return 1;
}

int qsort_strcmp_wrap(const void *a, const void *b)
{
	return strcmp(*((char**) a), *((char**) b));
}

void str_vec_sort(struct str_vec *v) {
	if (v->len < 2) {
		return;
	}
	qsort(v->array, v->len, sizeof(v->array[0]), qsort_strcmp_wrap);
	return;
}

/*
 * TODO: Just empties repeated items, does not remove.  Expects calling code to
 * check for empty strings.  That's ugly, see if we can cleanly fix.
 */
int str_vec_uniq(struct str_vec *v)
{
	if (v->len < 2) {
		return 0;
	}

	str_vec_sort(v);

	ssize_t i;
	for (i = 1; i < v->len; i++) {
		if (strcmp(v->array[i], v->array[i-1]) == 0) {
			v->array[i-1][0] = '\0';
		}
	}

	return 0;
}

/*
 * ============================================================================
 * miscellaneous/support
 * ============================================================================
 */

/*
 * Like strncat, except:
 * - Do not use trailing null; track offset into buffer instead
 * - Able to skip set number of input bytes before writing into buffer
 */
void strcatoffset(char *buf, const char *str, size_t *left_to_skip, size_t *written, size_t max)
{
	size_t str_len = strlen(str);
	int i = 0;

	if ((*left_to_skip) >= str_len) {
		(*left_to_skip) -= str_len;
		return;
	}

	if ((*left_to_skip) > 0) {
		i += (*left_to_skip);
		(*left_to_skip) = 0;
	}

	for (; i < str_len && (*written) < max; i++, (*written)++) {
		buf[(*written)] = str[i];
	}
}

/*
 * Writing to this filesystem is only used as a way to signal that the
 * configuration and should be reparsed.  Thus, it does not matter which
 * writing function is called - they should all act the same.  They all call
 * this.
 */
int write_attempt(const char* path)
{
	/*
	 * The *only* thing writable is the /reparse_config, and only by root.
	 * When it is written to, it will cause brp to reparse its configuration.
	 */
	if (strcmp(path, "/reparse_config") == 0) {
		struct fuse_context *context = fuse_get_context();
		if (context->uid != 0) {
			/* Non-root users cannot do anything with this file. */
			return -EACCES;
		} else {
			brp_parse_config();
			return 0;
		}
	} else {
		return -EACCES;
	}
}

static int brp_orig_cwd, brp_orig_root;

/*
 * Given an input path, finds the corresponding content to output (if any) and
 * populates various related fields (e.g. stat info) accordingly.
 *
 * Returns 0 if found, -ENOENT indicates not found
 *
 * If out_fd is not NULL, the file will be opened, and file descriptor assigned.
 */
int corresponding(char *in_path, int *out_fd, struct stat *stbuf,
		  struct out_item **arg_out_item, int *stratum_id,
		  struct in_item **arg_in_item, char **tail)
{
	/* handle root specially */
	if (in_path[0] == '/' && in_path[1] == '\0') {
		memcpy(stbuf, &parent_stat, sizeof(parent_stat));
		return 0;
	}

	int retval = -ENOENT;

	size_t i, j;
	size_t in_path_len = strlen(in_path);
	int st;
	char tmp_path[PATH_MAX + 1];
	int *stratum_root_fd = malloc(sizeof(int) * nstratum);

	int ret = seteuid(0);
	if (unlikely(ret < 0)) {
		perror("seteuid");
		exit(1);
	}

	ret = chdir(STRATA_ROOT);
	if (unlikely(ret < 0)) {
		// strata root missing?!
		perror("Failed to chdir to strata root");
		exit(1);
	}

	for (st = 0; st < nstratum; st++)
		stratum_root_fd[st] = open(stratum[st], O_RDONLY | O_DIRECTORY);

	for (st = 0; st < nstratum; st++) {
		if (unlikely(stratum_root_fd[st] < 0))
			continue;

		ret = fchdir(stratum_root_fd[st]);
		if (unlikely(ret < 0))
			continue;
		ret = chroot(".");
		if (unlikely(ret < 0))
			continue;

		/* check for a match on something contained in one of the configured
		 * directories */
		for (i = 0; i < out_item_count; i++) {
			if (strncmp(in_path, out_items[i].path,
				    out_items[i].path_len) ||
			    in_path[out_items[i].path_len] != '/' ||
			    out_items[i].file_type != FILE_TYPE_DIRECTORY)
				continue;
			struct in_item *in_item = out_items[i].in_items;
			for (j = 0; j < out_items[i].in_item_count; j++) {
				if (in_item[j].stratum_id >= 0 && in_item[j].stratum_id != st)
					continue;

				if (unlikely(in_item[j].path_len+in_path_len-out_items[i].path_len > PATH_MAX))
					continue;
				strcpy(tmp_path, in_item[j].path);
				strcat(tmp_path, in_path + out_items[i].path_len);

				ret = stat(tmp_path, stbuf);
				if (ret < 0)
					continue;

				// Check again with proper permission
				SET_CALLER_UID();
				ret = stat(tmp_path, stbuf);
				if (unlikely(ret < 0)) {
					ret = seteuid(0);
					if (unlikely(ret < 0)) {
						perror("seteuid");
						exit(1);
					}
					continue;
				}

				*arg_out_item = &out_items[i];
				*arg_in_item = &out_items[i].in_items[j];
				*stratum_id = st;
				*tail = in_path + out_items[i].path_len;

				if (out_fd)
					*out_fd = open(tmp_path, O_RDONLY);
				retval = 0;
				goto end;
			}
		}

		/*
		 * Check for a match on a virtual parent directory of a
		 * configured item.
		 */
		for (i = 0; i < out_item_count; i++) {
			if (strncmp(out_items[i].path, in_path, in_path_len) ||
			    (out_items[i].path[in_path_len] != '/' &&
			     out_items[i].path[in_path_len] != '\0'))
				continue;

			struct in_item *in_item = out_items[i].in_items;
			for (j = 0; j < out_items[i].in_item_count; j++) {
				if (in_item[j].stratum_id >= 0 && in_item[j].stratum_id != st)
					continue;

				int ret = stat(in_item[j].path, stbuf);
				if (ret < 0)
					continue;

				// Check again with proper permission
				SET_CALLER_UID();
				ret = stat(in_item[j].path, stbuf);
				if (unlikely(ret < 0)) {
					ret = seteuid(0);
					if (unlikely(ret < 0)) {
						perror("seteuid");
						exit(1);
					}
					continue;
				}
				*arg_out_item = &out_items[i];
				*arg_in_item = &out_items[i].in_items[j];
				*stratum_id = st;
				*tail = "";
				if (out_items[i].path[in_path_len] == '/' ||
				    out_items[i].file_type == FILE_TYPE_DIRECTORY)
					memcpy(stbuf, &parent_stat, sizeof(parent_stat));
				if (out_fd)
					*out_fd = open(tmp_path, O_RDONLY);
				retval = 0;
				goto end;
			}
		}
	}

end:
	for (st = 0; st < nstratum; st++)
		if (stratum_root_fd[st] > 0)
			close(stratum_root_fd[st]);

	free(stratum_root_fd);

	// If anything goes wrong here, we are stuck in a different root.
	// In that case we give up and quit.
	ret = seteuid(0);
	if (unlikely(ret < 0)) {
		perror("seteuid");
		exit(1);
	}
	ret = fchdir(brp_orig_root);
	if (unlikely(ret < 0)) {
		perror("Failed to chdir to original root");
		exit(1);
	}

	ret = chroot(".");
	if (unlikely(ret < 0)) {
		perror("Failed to chroot to original root");
		exit(1);
	}

	ret = fchdir(brp_orig_cwd);
	if (unlikely(ret < 0)) {
		perror("Failed to change back to old cwd");
		exit(1);
	}

	return retval;
}

/*
 * Apply relevant filter to getattr output.
 */
void stat_filter(struct stat *stbuf,
		int in_fd,
		int filter,
		int stratum_id,
		struct in_item *item,
		const char *tail)
{
	/*
	 * Remove an setuid/setgid properties and write properties  The
	 * program we are wrapping could be setuid and owned by something
	 * other than root, in which case this would have been an exploit.
	 * Moreover, no one can write to these.
	 */
	stbuf->st_mode &= ~ (S_ISUID | S_ISGID | S_IWUSR | S_IWGRP | S_IWOTH);

	if (S_ISDIR(stbuf->st_mode)) {
		/* filters below only touch files */
		close(in_fd);
		return;
	}

	FILE *fp;
	char line[PATH_MAX+1];

	switch (filter) {

	case FILTER_PASS:
		break;

	case FILTER_BRC_WRAP:
		stbuf->st_size = strlen("#!/bedrock/libexec/busybox sh\nexec /bedrock/bin/brc ")
						+ stratum_len[stratum_id]
						+ strlen(" ")
						+ item->path_len
						+ strlen(tail)
						+ strlen(" \"$@\"\n");
		break;

	case FILTER_EXEC:
		fp = fdopen(in_fd, "r");
		if (fp != NULL) {
			while (fgets(line, PATH_MAX, fp) != NULL) {
				if (strncmp(line, "Exec=", strlen("Exec=")) == 0 ||
						strncmp(line, "TryExec=", strlen("TryExec=")) == 0 ||
						strncmp(line, "ExecStart=", strlen("ExecStart=")) == 0 ||
						strncmp(line, "ExecStop=", strlen("ExecStop=")) == 0 ||
						strncmp(line, "ExecReload=", strlen("ExecReload=")) == 0) {
					stbuf->st_size += strlen("/bedrock/bin/brc ");
					stbuf->st_size += stratum_len[stratum_id];
					stbuf->st_size += strlen(" ");
				}
			}
			fclose(fp);
		}
		break;

	}
	close(in_fd);
}

/*
 * Do read() and apply relevant filter.
 */
int read_filter(int in_fd,
		int filter,
		int stratum_id,
		struct in_item *item,
		const char *tail,
		char *buf,
		size_t size,
		off_t offset)
{
	char *execs[] = {"TryExec=", "ExecStart=", "ExecStop=", "ExecReload=", "Exec="};
	size_t exec_cnt = sizeof(execs) / sizeof(execs[0]), left_to_skip, written;
	int ret;
	const size_t line_max = PATH_MAX;
	char line[line_max+1];
	FILE *fp;

	switch (filter) {

	case FILTER_PASS:
		ret = pread(in_fd, buf, size, offset);
		close(in_fd);
		return ret;

	case FILTER_BRC_WRAP:
		close(in_fd);

		left_to_skip = offset;
		written = 0;
		strcatoffset(buf, "#!/bedrock/libexec/busybox sh\nexec /bedrock/bin/brc ", &left_to_skip, &written, size);
		strcatoffset(buf, stratum[stratum_id], &left_to_skip, &written, size);
		strcatoffset(buf, " ", &left_to_skip, &written, size);
		strcatoffset(buf, item->path, &left_to_skip, &written, size);
		strcatoffset(buf, tail, &left_to_skip, &written, size);
		strcatoffset(buf, " \"$@\"\n", &left_to_skip, &written, size);
		return written;

	case FILTER_EXEC:
		left_to_skip = offset;
		written = 0;
		fp = fdopen(in_fd, "r");
		if (!fp) {
			int ret = errno;
			close(in_fd);
			return -ret;
		}
		while (fgets(line, line_max, fp) != NULL) {
			size_t i;
			int found = 0;
			for (i = 0; i < exec_cnt; i++) {
				if (strncmp(line, execs[i], strlen(execs[i])) == 0) {
					found = 1;
					strcatoffset(buf, execs[i], &left_to_skip, &written, size);
					strcatoffset(buf, "/bedrock/bin/brc ", &left_to_skip, &written, size);
					strcatoffset(buf, stratum[stratum_id], &left_to_skip, &written, size);
					strcatoffset(buf, " ", &left_to_skip, &written, size);
					strcatoffset(buf, line + strlen(execs[i]), &left_to_skip, &written, size);
				}
			}
			if (!found) {
				strcatoffset(buf, line, &left_to_skip, &written, size);
			}
			if (written >= size) {
				break;
			}
		}
		fclose(fp);
		return written;
	}

	return -ENOENT;
}

/*
 * ============================================================================
 * FUSE functions
 * ============================================================================
 */

/*
 * FUSE calls its equivalent of stat(2) "getattr".  This just gets stat
 * information, e.g. file size and permissions.
 */
static int brp_getattr(const char *in_path, struct stat *stbuf)
{
	SET_CALLER_UID();

	struct out_item *out_item;
	struct in_item *in_item;
	char *tail;
	char *config_str;
	int ret, fd;
	int stratum_id;

	if (in_path[0] == '/' && in_path[1] == '\0') {
		memcpy(stbuf, &parent_stat, sizeof(parent_stat));
		return 0;
	}

	if (strcmp(in_path, "/reparse_config") == 0) {
		memcpy(stbuf, &reparse_stat, sizeof(reparse_stat));
		config_str = config_contents();
		if (config_str) {
			stbuf->st_size = strlen(config_str);
			free(config_str);
			return 0;
		} else {
			return -ENOMEM;
		}
	}

	if ( (ret = corresponding((char*)in_path, &fd, stbuf, &out_item, &stratum_id, &in_item, &tail)) >= 0) {
		stat_filter(stbuf, fd, out_item->filter, stratum_id, in_item, tail);
		return 0;
	} else {
		return ret;
	}
}

/*
 * Provides contents of a directory, e.g. as used by `ls`.
 */
static int brp_readdir(const char *in_path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi)
{
	SET_CALLER_UID();

	(void)offset;
	(void)fi;

	char out_path[PATH_MAX + 1];
	size_t i, j;
	int st;
	size_t in_path_len = strlen(in_path);
	/* handle root directory specially */
	if (in_path_len == 1) {
		in_path_len = 0;
	}
	struct stat stbuf;
	struct in_item *in_item;
	int ret_val = -ENOENT;
	char *slash;
	int *stratum_root_fd = malloc(sizeof(int)*nstratum);

	int ret = chdir(STRATA_ROOT);
	if (unlikely(ret < 0)) {
		// strata root missing?!
		perror("Failed to chdir to strata root");
		exit(1);
	}

	for (st = 0; st < nstratum; st++)
		stratum_root_fd[st] = open(stratum[st], O_RDONLY|O_DIRECTORY);

	struct dirent *dir;

	struct str_vec v;
	str_vec_new(&v);

	for (st = 0; st < nstratum; st++) {
		if (unlikely(stratum_root_fd[st] < 0))
			continue;

		ret = seteuid(0);
		if (unlikely(ret < 0))
			return -errno;

		ret = fchdir(stratum_root_fd[st]);
		if (unlikely(ret < 0))
			continue;
		ret = chroot(".");
		if (unlikely(ret < 0))
			continue;

		SET_CALLER_UID();
		for (i = 0; i < out_item_count; i++) {
			/*
			 * Check for contents of one of the configured
			 * directories
			 */
			in_item = out_items[i].in_items;
			if (strncmp(in_path, out_items[i].path,
				    out_items[i].path_len) ||
			    (in_path[out_items[i].path_len] != '\0' &&
			     in_path[out_items[i].path_len] != '/') ||
			    out_items[i].file_type != FILE_TYPE_DIRECTORY)
				continue;
			for (j = 0; j < out_items[i].in_item_count; j++) {
				if (in_item[j].stratum_id >= 0 && in_item[j].stratum_id != st)
					continue;

				if (in_item[j].path_len + in_path_len -
				    out_items[i].path_len > PATH_MAX)
					continue;

				strcpy(out_path, in_item[j].path);
				strcat(out_path, in_path + out_items[i].path_len);

				ret = stat(out_path, &stbuf);
				if (ret < 0)
					continue;

				if (S_ISDIR(stbuf.st_mode)) {
					DIR *d = opendir(out_path);
					if (!d) {
						perror("opendir()");
						continue;
					}
					while ( (dir = readdir(d) )) {
						str_vec_append(&v, dir->d_name);
					}
					closedir(d);
				} else {
					if (strrchr(out_path, '/')) {
						str_vec_append(&v, strrchr(out_path, '/') + 1);
					} else {
						str_vec_append(&v, out_path);
					}
				}
			}
		}
		for (i = 0; i < out_item_count; i++) {
			/*
			 * Check for a match directly on one of the configured
			 * items or a virtual parent directory
			 */
			if (strncmp(out_items[i].path, in_path, in_path_len) ||
			    out_items[i].path[in_path_len] != '/')
				continue;

			in_item = out_items[i].in_items;
			for (j = 0; j < out_items[i].in_item_count; j++) {
				if (in_item[j].stratum_id >= 0 &&
				    in_item[j].stratum_id != st)
					continue;

				ret = stat(in_item[j].path, &stbuf);
				if (ret < 0)
					continue;
				if (out_items[i].path_len - in_path_len - 1 >
				    PATH_MAX)
					continue;
				strcpy(out_path,
				       out_items[i].path + in_path_len + 1);
				if ((slash = strchr(out_path, '/'))) {
					*slash = '\0';
				}
				str_vec_append(&v, out_path);
				break;
			}
		}
	}

	/*
	 * Handle reparse_config on root
	 */
	if (in_path[0] == '/' && in_path[1] == '\0') {
		str_vec_append(&v, "reparse_config");
	}

	str_vec_uniq(&v);
	for (i = 0; i < v.len; i++) {
		if (v.array[i][0] != '\0') {
			filler(buf, v.array[i], NULL, 0);
			ret_val = 0;
		}
	}

	str_vec_free(&v);

	for (st = 0; st < nstratum; st++)
		if (stratum_root_fd[st] >= 0)
			close(stratum_root_fd[st]);

	free(stratum_root_fd);

	// If anything goes wrong here, we are stuck in a different root.
	// In that case we give up and quit.
	ret = seteuid(0);
	if (unlikely(ret < 0)) {
		perror("seteuid");
		exit(1);
	}
	ret = fchdir(brp_orig_root);
	if (unlikely(ret < 0)) {
		perror("Failed to chdir to original root");
		exit(1);
	}

	ret = chroot(".");
	if (unlikely(ret < 0)) {
		perror("Failed to chroot to original root");
		exit(1);
	}

	ret = fchdir(brp_orig_cwd);
	if (unlikely(ret < 0)) {
		perror("Failed to change back to old cwd");
		exit(1);
	}

	return ret_val;
}

/*
 * Check if user has permissions to do something with file. e.g. read or write.
 */
static int brp_open(const char *in_path, struct fuse_file_info *fi)
{
	SET_CALLER_UID();

	struct out_item *out_item;
	int stratum_id;
	struct in_item *in_item;
	char *tail;
	int ret;
	struct stat stbuf;

	/*
	 * /reparse_config is the only file which could possibly be written to.
	 * Get that out of the way here so we can assume everything else later is
	 * only being read.
	 */
	if (strcmp(in_path, "/reparse_config") == 0) {
		struct fuse_context *context = fuse_get_context();
		if (context->uid != 0) {
			/* Non-root users cannot do anything with this file. */
			return -EACCES;
		} else {
			return 0;
		}
	}

	/*
	 * Everything else in this filesystem is read-only.  If the user requested
	 * anything else, return EACCES.
	 *
	 * Note the way permissions are stored in fi->flags do *not* have a single
	 * bit flag for read or write, hence the unusual looking check below.  See
	 * `man 2 open`.
	 */
	if ((fi->flags & 3) != O_RDONLY ) {
		return -EACCES;
	}

	if ( (ret = corresponding((char*)in_path, NULL, &stbuf, &out_item, &stratum_id, &in_item, &tail)) >= 0) {
		return 0;
	}
	return -ENOENT;
}

/*
 * Read file contents.
 */
static int brp_read(const char *in_path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
	(void)fi;
	SET_CALLER_UID();

	struct out_item *out_item;
	int stratum_id;
	struct in_item *in_item;
	char *tail;
	char *config_str;
	struct stat stbuf;
	int ret, fd;

	if (strcmp(in_path, "/reparse_config") == 0) {
		config_str = config_contents();
		if (!config_str) {
			return -ENOMEM;
		}
		ret = MIN(strlen(config_str + offset), size);
		memcpy(buf, config_str + offset, ret);
		free(config_str);
		return ret;
	}

	ret = corresponding((char*) in_path, &fd, &stbuf, &out_item, &stratum_id, &in_item, &tail);
	if (ret < 0) {
		return ret;
	}

	return read_filter(fd, out_item->filter, stratum_id, in_item, tail, buf, size, offset);
}

/*
 * This is typically used to write to a file, just as you'd expect from the
 * name.  However, for this filesystem, we only use it as an indication to
 * reload the configuration and stratum information.
 */
static int brp_write(const char *in_path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
	(void)size;
	(void)offset;
	(void)fi;
	SET_CALLER_UID();

	if (write_attempt(in_path) == 0) {
		return strlen(buf);
	} else {
		return -EACCES;
	}
}

/*
 * This is typically used to indicate a file should be shortened.  Like
 * write(), it is only being used here as an indication to reload the
 * configuration and stratum information.
 */
static int brp_truncate(const char *in_path, off_t length)
{
	SET_CALLER_UID();

	if (write_attempt(in_path) == 0) {
		return 0;
	} else {
		return -EACCES;
	}
}

static struct fuse_operations brp_oper = {
	.getattr  = brp_getattr,
	.readdir  = brp_readdir,
	.open     = brp_open,
	.read     = brp_read,
	.write    = brp_write,
	.truncate = brp_truncate,
};

/*
 * ============================================================================
 * main
 * ============================================================================
 */

int main(int argc, char *argv[])
{
	(void)argc;
	(void)argv;

	/*
	 * Ensure we are running as root so that any requests by root to this
	 * filesystem can be provided.
	 */
	if (getuid() != 0) {
		fprintf(stderr, "ERROR: not running as root, aborting.\n");
		return 1;
	}

	brp_orig_cwd = open(".", O_RDONLY|O_DIRECTORY);
	if (brp_orig_cwd < 0) {
		perror("Failed to open working directory");
		return 1;
	}

	brp_orig_root = open("/", O_RDONLY|O_DIRECTORY);
	if (brp_orig_root < 0) {
		perror("Failed to open root directory");
		return 1;
	}

	 /*
	  * The mount point should be provided.
	  */
	if (argc < 2) {
		fprintf(stderr, "ERROR: Insufficient arguments.\n");
		return 1;
	}

	/*
	 * The mount point should exist.
	 */
	struct stat test_is_dir_stat;
	if (stat(argv[1], &test_is_dir_stat) != 0 || S_ISDIR(test_is_dir_stat.st_mode) == 0) {
		fprintf(stderr, "ERROR: Could not find directory \"%s\"\n", argv[1]);
		return 1;
	}

	/*
	 * Default stat() values for certain output files.  Some of these may be
	 * called quite a lot in quick succession; better to calculate them here
	 * and memcpy() them over than calculate on-the-fly.
	 */

	memset(&parent_stat, 0, sizeof(struct stat));
	parent_stat.st_ctime = parent_stat.st_mtime = parent_stat.st_atime = time(NULL);
	parent_stat.st_mode = S_IFDIR | 0555;

	memcpy(&reparse_stat, &parent_stat, sizeof(struct stat));
	reparse_stat.st_mode = S_IFREG | 0600;

	/*
	 * Generate arguments for fuse:
	 * - start with no arguments
	 * - add argv[0] (which I think is just ignored)
	 * - add mount point
	 * - disable multithreading, as with the UID/GID switching it will result
	 *   in abusable race conditions.
	 * - add argument to:
	 *   - let all users access filesystem
	 *   - allow mounting over non-empty directories
	 */
	struct fuse_args args = FUSE_ARGS_INIT(0, NULL);
	fuse_opt_add_arg(&args, argv[0]);
	fuse_opt_add_arg(&args, argv[1]);
	fuse_opt_add_arg(&args, "-s");
	fuse_opt_add_arg(&args, "-oallow_other,nonempty");
	/* stay in foreground, useful for debugging */
	fuse_opt_add_arg(&args, "-f");

	/* initial config parse */
	brp_parse_config();

	return fuse_main(args.argc, args.argv, &brp_oper, NULL);
}
