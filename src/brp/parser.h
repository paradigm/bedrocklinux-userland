#pragma once

#include <stdlib.h>
#include <stdio.h>

struct rhs {
	char *str;
	size_t len;
	struct rhs *next;
};
struct entry {
	char *lhs;
	size_t lhs_len;
	int nrhs;
	struct rhs *r;
	struct entry *next;
};
struct section {
	char *name;
	size_t name_len;
	int nent;
	struct entry *e;
	struct section *next;
};

static inline void free_sections(struct section *sec_head) {
	struct entry *e_curr;
	struct rhs *rhs_curr;
	while(sec_head) {
		free(sec_head->name);
		e_curr = sec_head->e;
		while(e_curr) {
			free(e_curr->lhs);
			rhs_curr = e_curr->r;
			while(rhs_curr) {
				struct rhs *tmp = rhs_curr->next;
				free(rhs_curr->str);
				free(rhs_curr);
				rhs_curr = tmp;
			}

			struct entry *tmp = e_curr->next;
			free(e_curr);
			e_curr = tmp;
		}

		struct section *tmp = sec_head->next;
		free(sec_head);
		sec_head = tmp;
	}
}
static inline void print_sections(struct section *sec_head) {
	struct entry *e_curr;
	struct rhs *rhs_curr;
	while(sec_head) {
		printf("[%s] (%d)\n", sec_head->name, sec_head->nent);
		e_curr = sec_head->e;
		while(e_curr) {
			printf("%s (%d)", e_curr->lhs, e_curr->nrhs);
			if (e_curr->r)
				printf(" = ");
			else
				printf("\n");
			rhs_curr = e_curr->r;
			while(rhs_curr) {
				if (rhs_curr->next)
					printf("%s, ", rhs_curr->str);
				else
					printf("%s\n", rhs_curr->str);
				rhs_curr = rhs_curr->next;
			}
			e_curr = e_curr->next;
		}

		sec_head = sec_head->next;
	}
}

struct section *parse_config(const char *, int *);
