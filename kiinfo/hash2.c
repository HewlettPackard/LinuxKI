/***************************************************************************
Copyright 2017 Hewlett Packard Enterprise Development LP.
This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or (at
your option) any later version. This program is distributed in the
hope that it will be useful, but WITHOUT ANY WARRANTY; without even
the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
PURPOSE. See the GNU General Public License for more details. You
should have received a copy of the GNU General Public License along
with this program; if not, write to the Free Software Foundation,
Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
***************************************************************************/

#include <stdio.h> 
#include <stdlib.h>
#include <string.h>
#include <sys/errno.h>
#include <sys/types.h>
#include "ki_tool.h"
#include "liki.h"
#include "globals.h"
#include "developers.h"
#include "hash.h"

/*
**  similar to find_add_hash_entry2, but uses 2 key words to match 
*/
lle2_t *
find_add_hash_entry2 (lle2_t ***hashaddr, int hashsz, uint64 key1, uint64 key2, int idx, int size)
{
lle2_t **hashptr;
lle2_t *prevptr, *entryptr;
int	linkcnt=0;

	hashptr = *hashaddr;
	if ((idx < 0) || idx > (hashsz)) {
		fprintf (stderr, "Suspect hash index passed to find_add_hash_entry\n");
		fprintf (stderr, "find_add_hash_entry2(hashptr: 0x%llx, hashsz %d, key1: 0x%llx key2: 0x%llx idx: 0x%x (%d), size %d)\n", hashptr, hashsz, key1, key2, idx, idx, size);  
		/* the following can be used to force a coredump  */
		entryptr = NULL;
		entryptr->next = 0;
		FATAL(3200, "Invalid hash index", "idx:", idx);
	}
	if (hashptr == NULL) {
		hashptr = calloc(hashsz, sizeof(uint64 *));
		if (hashptr == NULL) {
			FATAL(errno, "Unable to malloc hash table", "hashsz:", hashsz);
		}
		CALLOC_LOG(hashptr, hashsz, sizeof(uint64 *));

		*hashaddr = hashptr;
	}

	prevptr = (lle2_t *)&hashptr[idx];
	entryptr = (lle2_t *)hashptr[idx];
	while (entryptr != NULL) {
		if ((entryptr->key1 == key1) && (entryptr->key2 == key2))  {
			return entryptr;
		}
		prevptr = entryptr;
		entryptr = entryptr->next;
		linkcnt++;
	}

	if (entryptr == NULL) {
#if DEBUG
		if ((debug) && (linkcnt > 2)) 
			printf ("find_add_hash_entry2(): key1 0x%llx key2 0x%llx, linkcnt %d\n",
				key1, key2, linkcnt);
#endif
			
		entryptr = calloc(1, size);
		if (entryptr == NULL) {
			FATAL(errno, "Unable to malloc hash entry", "size:", size);
		}
		CALLOC_LOG(entryptr, 1, size);
		entryptr->key1 = key1;
		entryptr->key2 = key2;
		entryptr->next = NULL;
		prevptr->next = entryptr;
	}

#if DEBUG
#endif
	return entryptr;
}


/*
**
*/
lle2_t *
find_add_entry2 (lle2_t **hashptr, uint64 key1, uint64 key2, int idx, int size)
{
lle2_t *prevptr, *entryptr;
int	linkcnt=0;

/*	if (debug) printf ("find_add_entry2(0x%llx, 0x%llx, 0x%llx 0x%x, 0x%x)\n", hashptr, key1, key2, idx, size);  */

	prevptr = (lle2_t *)&hashptr[idx];
	entryptr = (lle2_t *)hashptr[idx];
	while (entryptr != NULL) {
		if ((entryptr->key1 == key1) && (entryptr->key2 == key2))  {
/*			if (debug) printf ("Exiting find_add_entry2() - existing entry found\n"); */
			return entryptr;
		}
		prevptr = entryptr;
		entryptr = entryptr->next;
		linkcnt++;
	}

	if (entryptr == NULL) {
		if ((debug) && (linkcnt > 2)) 
			printf ("find_add_entry2(): key1 0x%llx, key2 0x%llx, linkcnt %d\n",
				key1, key2, linkcnt);
		entryptr = calloc(1, size);
		if (entryptr == NULL) {
			FATAL(errno, "Unable to malloc hash entry", "size:", size);
		}
		CALLOC_LOG(entryptr, 1, size);
		entryptr->key1 = key1;
		entryptr->key2 = key2;
		entryptr->next = NULL;
		prevptr->next = entryptr;
	}
 
/*	if (debug) printf ("Exiting find_add_entry2() - new entry created\n"); */
	return entryptr;
	
}

/*
**
*/
lle2_t *
add_entry_head2 (lle2_t **headptr, uint64 key1, uint64 key2, int size)
{
lle2_t *nextptr, *entryptr;

	nextptr = (lle2_t *)*headptr;

	entryptr = calloc(1, size);
	if (entryptr == NULL) {
		FATAL(errno, "Unable to malloc hash entry", "size:", size);
	}
	CALLOC_LOG(entryptr, 1, size);
	entryptr->key1 = key1;
	entryptr->next = nextptr;
	*headptr = entryptr;

	return entryptr;
}

/*
**
*/
lle2_t * 
find_entry2(lle2_t **hashptr, uint64 key1, uint64 key2, int idx)
{
	lle2_t	*entryptr;

	if (hashptr == NULL) return NULL;

	entryptr = (lle2_t *)hashptr[idx]; 	
	while (entryptr != NULL) {
		if ((entryptr->key1 == key1)  && (entryptr->key2 == key2))
			return entryptr;
		entryptr = entryptr->next;
	}

	return NULL;
}

void
foreach_hash_entry2(void **arg, int hsize, int (*work_func)(void *, void *), int (*sort_func)(const void *, const void *), int32 cnt, void *work_arg) 
{
	lle2_t **hashptr = (lle2_t **)arg;
	lle2_t *entryptr;
	uint64 *tmpsort;
	int	tmpcnt;
	int	tmpsortc;
	int i;

	if (hashptr == NULL) return;

	tmpsortc = hsize * 2;
	tmpsort = malloc(sizeof(lle2_t *) * hsize * 2);
	MALLOC_LOG(tmpsort, sizeof(lle2_t *) * hsize * 2);
	tmpcnt = 0;

	for (i=0; i < hsize; i++) {
		entryptr = hashptr[i];
		while (entryptr != NULL) {
			if (sort_func && sort_flag) { 
				if (tmpcnt == tmpsortc) {
					tmpsortc += hsize*2;
					tmpsort = realloc((uint64 *)tmpsort, sizeof(lle2_t *) * tmpsortc);
				}

				*(tmpsort + tmpcnt++) = (uint64)entryptr;
			} else { 
				work_func((void *)entryptr, work_arg);
			}

			entryptr = (void *)entryptr->next;
		}
	}

	if ((sort_func == NULL) || !sort_flag) {
		return;
	}

	if ((tmpcnt > 1) && sort_flag) {
		qsort (tmpsort, tmpcnt, sizeof(lle2_t *), sort_func);
	}

	if (tmpcnt > 0) {
		for (i = 0; i < tmpcnt; i++) {
			entryptr = (lle2_t *)*(tmpsort + i);

			if ((cnt < 0) && (i < -cnt)) continue;
	
			work_func((void *)entryptr, work_arg);

			if ((cnt > 0) && ((i+1) == cnt)) i = tmpcnt;
		}
	}

	FREE(tmpsort);
}

/*
**  similar to find_add_hash_entry, but for doubly linked lists 
*/
lle2_t *
find_remove_hash_entry2 (lle2_t ***hashaddr, int hashsz, uint64 key1, uint64 key2, int idx, int size)
{
lle2_t **hashptr;
lle2_t *prevptr, *entryptr;
int	linkcnt=0;

	hashptr = *hashaddr;
	if ((idx < 0) || idx > (hashsz)) {
		fprintf (stderr, "Suspect hash index passed to find_add_hash_entry\n");
		fprintf (stderr, "find_add_hash_entry(hashptr: 0x%llx, hashsz %d, key1: 0x%llx key2: 0x%llx idx: 0x%x (%d), size %d)\n", hashptr, hashsz, key1, key2, idx, idx, size);  
		FATAL(3201, "Invalid hash index", "idx:", idx);
	}

	if (hashptr == NULL) {
		return(NULL);
	}

	prevptr = (lle2_t *)&hashptr[idx];
	entryptr = (lle2_t *)hashptr[idx];
	while (entryptr != NULL) {
		if ((entryptr->key1 == key1) && (entryptr->key2 == key2))  {
			prevptr->next = entryptr->next;
			return entryptr;
		}
		prevptr = entryptr;
		entryptr = entryptr->next;
		linkcnt++;
	}

	return(NULL);
}
