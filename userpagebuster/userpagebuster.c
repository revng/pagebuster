/*
 * Userspace PoC of PageBuster
 *
 * Copyright (C) 2021  Matteo Giordano
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#define _POSIX_C_SOURCE 200809L
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <execinfo.h>
#include <signal.h>
#include <ucontext.h>
#include <gmodule.h>

#define pagesize getpagesize()

#if !defined(__linux__) || !defined(__x86_64__)
#error This example only works in Linux on x86-64.
#endif

void init(void) __attribute__((constructor));

/*
 * Structure for a memory area to be tracked.
 *
 * Entry of the doubly-linked list.
 *
 */
struct marea {

	/* mprotect/mmap address */
	void *addr;

	/* mprotect/mmap access flag */
	int prot;
};

/* Utils */
struct marea *new_marea(void *addr, int prot);
void free_marea(gpointer marea);
int compare(gconstpointer a, gconstpointer b);
int search(gconstpointer a, gconstpointer b);

void dump(void* addr, size_t __len);
void *(*real_mmap)(void *, size_t, int, int, int, off_t);
int (*real_mprotect)(void *, size_t, int);

/* Global variables */
char *counter_filename = "/tmp/counter";
int current_epoch;
GSList *hareas;
struct sigaction def_sigsegv;


/* Custom handler for intercept SIGSEGV in the target process */
void handler(int signal, siginfo_t *siginfo, void *contextptr)
{
	ucontext_t *const ctx = (ucontext_t *const) contextptr;

	if (real_mprotect == NULL) {
		real_mprotect = (int (*)(void *, size_t, int))dlsym(RTLD_NEXT, "mprotect");
	}

	/* Check if INDUCED sigsegv */
	GSList *node = g_slist_find_custom(hareas, siginfo->si_addr, search);

	/* Standard SIGSEGV handling */
	if (node == NULL) {

		if (def_sigsegv.sa_flags & SA_SIGINFO)
			(*def_sigsegv.sa_sigaction)(signal, siginfo, contextptr);
		else
			(*def_sigsegv.sa_handler)(signal);

	/* Custom SIGSEGV handling */
	} else {

		struct marea *found = (struct marea*) node->data;

		/* Invalid write attempt */
		if (ctx->uc_mcontext.gregs[REG_ERR] & 2){

			int new_permissions = found->prot;
			new_permissions &= ~PROT_EXEC;

			real_mprotect(found->addr, pagesize, new_permissions);

		/* Bad jump */
		} else if (ctx->uc_mcontext.gregs[REG_ERR] & 16) {

			int new_permissions = found->prot;
			new_permissions &= ~PROT_WRITE;

			dump(found->addr, pagesize);

			hareas = g_slist_remove(hareas, found);

			real_mprotect(found->addr, pagesize, new_permissions);
			free_marea(found);
		}
	}
}


void init(void)
{
	struct sigaction act;
	memset(&act, 0, sizeof(struct sigaction));
	sigemptyset(&act.sa_mask);
	act.sa_sigaction = handler;
	act.sa_flags = SA_SIGINFO | SA_ONSTACK;

	sigaction(SIGSEGV, &act, &def_sigsegv);

	hareas = NULL;
}

/* mmap hijack */
void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)
{
	int n_pages;

	size_t quot = length / pagesize;
	size_t rem = length % pagesize;

	/* Compute the number of pages */
	if(rem == 0)
		n_pages = quot;
	else
		n_pages = quot + 1;

	if (real_mmap == NULL){
		real_mmap = (void *(*)(void *, size_t, int, int, int, off_t)) dlsym(RTLD_NEXT, "mmap");
	}

	if(prot >= (PROT_EXEC | PROT_WRITE)) {

		int intended_permissions = prot;
		prot &= ~PROT_WRITE;

		void *real_address = real_mmap(addr, length, prot, flags, fd, offset);

		/* Create an entry for each page allocated by the mmap */
		for (int i = 0; i < n_pages; i++){
			hareas = g_slist_insert_sorted (hareas, (gpointer) new_marea(real_address + (i * pagesize), intended_permissions), compare);
		}

		return real_address;

	} else {

		return real_mmap(addr, length, prot, flags, fd, offset);
	}
}

/* mprotect hijack */
int mprotect(void *__addr, size_t __len, int __prot)
{
	int n_pages;

	size_t quot = __len / pagesize;
	size_t rem = __len % pagesize;

	/* Compute the number of pages */
	if(rem == 0)
		n_pages = quot;
	else
		n_pages = quot + 1;

	if(__prot >= (PROT_EXEC | PROT_WRITE)){

		/* Create an entry for each page covered by the mprotect */
		for (int i = 0; i < n_pages; i++){
			hareas = g_slist_insert_sorted (hareas, (gpointer) new_marea(__addr + (i * pagesize), __prot), compare);
		}

		/* Adjust the protection flags */
		__prot &= ~PROT_WRITE;

	/* W and X permissions are put in different time instants */
	} else if ((__prot == PROT_EXEC) || (__prot == (PROT_EXEC | PROT_READ))) {
		dump(__addr, __len);
	}

	if (real_mprotect == NULL){
		real_mprotect = (int (*)(void *, size_t, int)) dlsym(RTLD_NEXT, "mprotect");
	}
	return real_mprotect(__addr, __len, __prot);
}

void dump(void *addr, size_t __len)
{
	/* Global counter for epochs */
	FILE *counter;
	if(access(counter_filename, F_OK) != -1) {

		counter = fopen(counter_filename, "r+");
	} else {

		counter = fopen(counter_filename, "w+");
		fprintf(counter, "%d", 0);
	}

	if(counter == NULL){
		printf("Unable to create/open file.\n");
		exit(EXIT_FAILURE);
	}

	fscanf(counter, "%d", &current_epoch);

	FILE *fPtr;
	char title[100];
	sprintf(title, "%p_%d", addr, current_epoch);

	fPtr = fopen(title, "wb");
	if(fPtr == NULL){
		printf("Unable to create/open file.\n");
		exit(EXIT_FAILURE);
	}

	/* Dump */
	fwrite(addr, __len, 1, fPtr);

	/* Global counter update */
	fclose(counter);
	counter = fopen(counter_filename, "w");
	fprintf(counter, "%d", ++current_epoch);

	fclose(fPtr);
	fclose(counter);
}

/* Allocates space for a new struct marea */
struct marea *new_marea(void *addr, int prot)
{
	struct marea *new_m = (struct marea *) malloc(sizeof(struct marea));
	if (new_m) {
		new_m->addr = addr;
		new_m->prot = prot;
	}

	return new_m;
}

/* Frees the allocated space for struct marea */
void free_marea(gpointer marea)
{
	free((struct marea *) marea);
}

/* Order criterion for the list --> growing addresses */
int compare(gconstpointer a, gconstpointer b)
{
	GSList *elem_a = (GSList *)a;
	GSList *elem_b = (GSList *)b;

	return ((struct marea *) elem_a)->addr > ((struct marea *) elem_b)->addr;
}

int search(gconstpointer a, gconstpointer b)
{

	GSList *target_elem = (GSList *)a;
	void *addr_given = (void *)b;

	void *start_addr_iter = ((struct marea *) target_elem)->addr;
	void *end_addr_iter = start_addr_iter + pagesize -1;

	return !(addr_given >= start_addr_iter && addr_given <= end_addr_iter);
}
