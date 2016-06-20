#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>

#include "parser.h"

static inline void skip_until_newline(FILE *f, int *line, int *col) {
	char *buf = NULL;
	size_t n = 0;
	getline(&buf, &n, f);
	free(buf);
	(*line)++;
	*col = 0;
}

static inline void skip_spaces(FILE *f, int *line, int *col) {
	int c;
	while(isspace(c = fgetc(f)) && c != EOF) {
		if (c == '\n') {
			(*line)++;
			*col = 0;
		} else
			(*col)++;
	}
	if (c != EOF)
		ungetc(c, f);
}

struct _buffer {
	char *buf;
	size_t sz, len;
};

static inline void push_char(int c, struct _buffer *buf) {
	if (buf->len+1 >= buf->sz) {
		buf->sz = buf->sz ? buf->sz*2 : 64;
		buf->buf = realloc(buf->buf, buf->sz);
	}
	buf->buf[buf->len++] = (char)c;
}

static inline void init_buf(struct _buffer *buf) {
	buf->buf = (void *)(buf->sz = buf->len = 0);
}

static inline char *finalize_buf(struct _buffer *buf) {
	char *ret = buf->buf;
	if (!ret)
		return NULL;

	ret[buf->len] = '\0';
	init_buf(buf);
	return ret;
}

struct section *
parse_config(const char *file, int *_nsec) {
	FILE *cfg = fopen(file, "r");
	struct _buffer buf = {0};
	struct section *sec_head = NULL, **sec_next = &sec_head, *sec_curr;
	struct entry **e_next = NULL, *e_curr;
	struct rhs **rhs_next = NULL, *rhs_curr;
	int nsec = 0;
	int line = 1, col = 0;
	int c;
	if (!cfg)
		return NULL;

	enum {
		LHS,
		RHS,
		SECTION,
		PRELHS,
		PRERHS
	} state = PRELHS;
	do {
		c = fgetc(cfg);
		if (c == '\n') {
			line++;
			col = 0;
		} else
			col++;
		//fprintf(stderr, "%d, %d: %c\n", line, col, c);
		if (c == '#') {
			skip_until_newline(cfg, &line, &col);
			c = '\n';
		}
		if (isspace(c)) {
			if (state == LHS)
				goto lhs_end;
			else if (state == PRELHS || state == PRERHS) {
				skip_spaces(cfg, &line, &col);
				continue;
			}
		}
		if (c == EOF) {
		handle_eof:
			switch(state) {
			case PRELHS: case PRERHS:
				goto end;
			case RHS:
				goto rhs_end;
			case LHS:
				goto lhs_end;
			case SECTION:
				goto err;
			}
		}
		switch(c) {
		case '\\':
			c = fgetc(cfg);
			if (c == EOF)
				goto handle_eof;
			if (c == '\n') {
				line++;
				col = 0;
			} else
				col++;
			goto plain_char;
		case '[':
			// New section
			if (state != PRELHS)
				goto plain_char;
			state = SECTION;
			break;
		case ']':
			if (state != SECTION)
				goto plain_char;
			*sec_next = malloc(sizeof(struct section));
			sec_curr = *sec_next;
			memset(sec_curr, 0, sizeof(*sec_curr));
			sec_curr->name_len = buf.len;
			sec_curr->name = finalize_buf(&buf);
			sec_next = &sec_curr->next;
			e_next = &sec_curr->e;
			skip_spaces(cfg, &line, &col);
			state = PRELHS;
			nsec++;
			break;
		case ',':
		case '\n':
			if (state != RHS)
				goto plain_char;
			if (!buf.buf)
				//Empty rhs, ignore
				goto rhs_end;
			*rhs_next = malloc(sizeof(struct rhs));
			rhs_curr = *rhs_next;
			rhs_curr->next = NULL;
			rhs_curr->len = buf.len;
			rhs_curr->str = finalize_buf(&buf);
			rhs_next = &rhs_curr->next;
			e_curr->nrhs++;
			skip_spaces(cfg, &line, &col);
		rhs_end:
			if (c == ',')
				break;
			//End of entry
			state = PRELHS;
			break;
		case '=':
		lhs_end:
			if (state == PRERHS) {
				state = RHS;
				skip_spaces(cfg, &line, &col);
				break;
			}
			if (state != LHS)
				goto plain_char;
			*e_next = malloc(sizeof(struct entry));
			e_curr = *e_next;
			memset(e_curr, 0, sizeof(*e_curr));
			e_next = &e_curr->next;
			e_curr->lhs_len = buf.len;
			e_curr->lhs = finalize_buf(&buf);
			sec_curr->nent++;
			rhs_next = &e_curr->r;
			skip_spaces(cfg, &line, &col);
			state = c == '=' ? RHS : PRERHS;
			break;
		default:
		plain_char:
			if (state == PRELHS) {
				if (sec_head == NULL)
					return NULL;
				state = LHS;
			} else if (state == PRERHS)
				state = LHS;
			if (c == EOF)
				break;
			push_char(c, &buf);
		}
	} while(c != EOF);
end:
	fclose(cfg);
	*_nsec = nsec;
	return sec_head;
err:
	fclose(cfg);
	*_nsec = 0;
	free(buf.buf);
	free_sections(sec_head);

	fprintf(stderr, "Failed to parse config, line %d, col %d: Unexpected '%c'\n", line, col, c);
	return NULL;
}
