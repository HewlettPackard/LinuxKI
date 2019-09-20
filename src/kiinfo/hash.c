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

#define UNKNOWN_WCHAN 0x11335577ull

/*
**  similar to find_hash_entry, but also creates hash table if it does not exist
*/
lle_t *
find_add_hash_entry (lle_t ***hashaddr, int hashsz, uint64 key, int idx, int size)
{
lle_t **hashptr;
lle_t *prevptr, *entryptr;
#if DEBUG
int	linkcnt=0;
#endif


	hashptr = *hashaddr;
	if ((idx < 0) || idx > (hashsz)) {
		fprintf (stderr, "Suspect hash index passed to find_add_hash_entry\n");
		fprintf (stderr, "find_add_hash_entry(hashptr: 0x%llx, hashsz %d, key: 0x%llx idx: 0x%x (%d), size %d)\n", hashptr, hashsz, key, idx, idx, size);  
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

	prevptr = (lle_t *)&hashptr[idx];
	entryptr = (lle_t *)hashptr[idx];
	while (entryptr != NULL) {
		if (entryptr->key == key)  {
			return entryptr;
		}
		prevptr = entryptr;
		entryptr = entryptr->next;
#if DEBUG
		linkcnt++;
#endif
	}

	if (entryptr == NULL) {
#if DEBUG
		if ((debug) && (linkcnt > 2)) 
			printf ("find_add_hash_entry(): key 0x%llx, linkcnt %d\n",
				key, linkcnt);
#endif
			
		entryptr = calloc(1, size);
		if (entryptr == NULL) {
			FATAL(errno, "Unable to malloc hash entry", "size:", size);
		}
		CALLOC_LOG(entryptr, 1, size);

		entryptr->key = key;
		entryptr->next = NULL;
		prevptr->next = entryptr;
	}

#if DEBUG
	printf ("Exiting find_add_hash_entry() - new entry created 0x%llx\n", entryptr); 
#endif
	return entryptr;
}

/*
**      Stack trace version of find_add_hash_entry
*/
stklle_t *
find_add_stkhash_entry (stklle_t ***hashaddr, int hashsz, int idx, int size, uint64 *stktrc, int stklen)
{
stklle_t **hashptr;
stklle_t *prevptr, *entryptr;
stktrc_info_t *stkptr;
#if DEBUG
int     linkcnt=0;
#endif

#if DEBUG
        if (debug) printf ("find_add_stkhash_entry(%s %d)\n", p4_a2f(stktrc[0]), idx);
#endif
        hashptr = *hashaddr;
        if (hashptr == NULL) {
                hashptr = calloc(hashsz, sizeof(uint64 *));
                if (hashptr == NULL) {
			FATAL(errno, "Unable to malloc hash entry", "hashsz:", hashsz);
                }
		CALLOC_LOG(hashptr, hashsz, sizeof(uint64 *));

                *hashaddr = hashptr;
        }
	if (stklen > LEGACY_STACK_DEPTH) stklen = LEGACY_STACK_DEPTH;
        prevptr = (stklle_t *)&hashptr[idx];
        entryptr = (stklle_t *)hashptr[idx];
        while (entryptr != NULL) {
		stkptr = (stktrc_info_t *)entryptr;
	
                if ( !bcmp(&entryptr->key,stktrc,stklen * sizeof(uint64)) ) {
/*
               		printf("stk cnt=%d  ",stkptr->cnt);
			printf ("find_add_stkhash_entry(%s %d)\n", p4_a2f(stktrc[0]), idx);
*/
		        return entryptr;

		}
                prevptr = entryptr;
                entryptr = entryptr->next;
#if DEBUG
                linkcnt++;
#endif
        }

        if (entryptr == NULL) {
        
                entryptr = calloc(1, size);
                if (entryptr == NULL) {
			FATAL(errno, "Unable to malloc hash entry", "size:", size);
                }
		CALLOC_LOG(entryptr, 1, size);
                bcopy(stktrc,entryptr->key,(stklen * sizeof(uint64))); 
                entryptr->next = NULL;
                prevptr->next = entryptr;
        }
 
/*      if (debug) printf ("Exiting find_add_stkhash_entry() - new entry created\n"); */
        return entryptr;
}
 



/*
**
*/
lle_t *
find_add_entry (lle_t **hashptr, uint64 key, int idx, int size)
{
lle_t *prevptr, *entryptr;
#if DEBUG
int	linkcnt=0;
#endif

/*	if (debug) printf ("find_add_entry(0x%llx, 0x%llx, 0x%x, 0x%x)\n", hashptr, key, idx, size);  */

	prevptr = (lle_t *)&hashptr[idx];
	entryptr = (lle_t *)hashptr[idx];
	while (entryptr != NULL) {
		if (entryptr->key == key)  {
/*			if (debug) printf ("Exiting find_add_entry() - existing entry found\n"); */
			return entryptr;
		}
		prevptr = entryptr;
		entryptr = entryptr->next;
#if DEBUG
		linkcnt++;
#endif
	}

	if (entryptr == NULL) {
#if DEBUG
		if ((debug) && (linkcnt > 2)) 
			printf ("find_add_entry(): key 0x%llx, linkcnt %d\n",
				key, linkcnt);
#endif
		entryptr = calloc(1, size);
		if (entryptr == NULL) {
			FATAL(errno, "Unable to malloc hash entry", "size:", size);
		}
		CALLOC_LOG(entryptr, 1, size);
		entryptr->key = key;
		entryptr->next = NULL;
		prevptr->next = entryptr;
	}
 
/*	if (debug) printf ("Exiting find_add_entry() - new entry created\n"); */
	return entryptr;
	
}

/*
**
*/
lle_t *
add_entry_head (lle_t **headptr, uint64 key, int size)
{
lle_t *nextptr, *entryptr;

	nextptr = (lle_t *)*headptr;

	entryptr = calloc(1, size);
	if (entryptr == NULL) {
		FATAL(errno, "Unable to malloc hash entry", "size:", size);
	}
	CALLOC_LOG(entryptr, 1, size);
	entryptr->key = key;
	entryptr->next = nextptr;
	*headptr = entryptr;

	return entryptr;
}

/*
**
*/
void *
find_add_info (void **infoptr_addr, int size)
{
void *infoptr;

/*	if (debug) printf ("find_add_info()\n"); */

	infoptr = *infoptr_addr;
	if (infoptr == NULL) {
		infoptr = calloc(1, size);
		if (infoptr == NULL) {
			FATAL(errno, "Unable to malloc info structure", "size:", size);
		}
		CALLOC_LOG(infoptr, 1, size);

		*infoptr_addr = infoptr;
	}
	return (void *)infoptr;
}


/*
**
*/
lle_t * 
find_entry(lle_t **hashptr, uint64 key, int idx)
{
	lle_t	*entryptr;

	if (hashptr == NULL) return NULL;

	entryptr = (lle_t *)hashptr[idx]; 	
	while (entryptr != NULL) {
		if (entryptr->key == key) 
			return entryptr;
		entryptr = entryptr->next;
	}

	return NULL;
}

void
foreach_hash_entry(void **arg, int hsize, int (*work_func)(void *, void *), int (*sort_func)(const void *, const void *), int32 cnt, void *work_arg) 
{
	lle_t **hashptr = (lle_t **)arg;
	lle_t *entryptr;
	uint64 *tmpsort;
	int	tmpcnt;
	int	tmpsortc;
	int i;

	if (hashptr == NULL) return;

	tmpsortc = hsize * 2;
	tmpsort = malloc(sizeof(lle_t *) * hsize * 2);
	MALLOC_LOG(tmpsort, sizeof(lle_t *) * hsize * 2);
	tmpcnt = 0;

	for (i=0; i < hsize; i++) {
		entryptr = hashptr[i];
		while (entryptr != NULL) {
			if (sort_func && sort_flag) { 
				if (tmpcnt == tmpsortc) {
					tmpsortc += hsize*2;
					tmpsort = realloc((uint64 *)tmpsort, sizeof(lle_t *) * tmpsortc);
				}

				*(tmpsort + tmpcnt++) = (uint64)entryptr;
			} else { 
				work_func((void *)entryptr, work_arg);
			}

			entryptr = (void *)entryptr->next;
		}
	}

	if ((sort_func == NULL) || !sort_flag) {
		FREE(tmpsort);
		return;
	}

	if ((tmpcnt > 1) && sort_flag) {
		qsort (tmpsort, tmpcnt, sizeof(lle_t *), sort_func);
	}

	if (tmpcnt > 0) {
		for (i = 0; i < tmpcnt; i++) {
			entryptr = (lle_t *)*(tmpsort + i);

			if ((cnt < 0) && (i < -cnt)) continue;
	
			work_func((void *)entryptr, work_arg);

			if ((cnt > 0) && ((i+1) == cnt)) i = tmpcnt;
		}
	}

	FREE(tmpsort);
}

/*
** This is special function that allows the "unknown" function to be listed at the bottom
*/
void
foreach_hash_entry_l(void **arg, int hsize, int (*work_func)(void *, void *), int (*sort_func)(const void *, const void *), int32 cnt, void *work_arg) 
{
	lle_t **hashptr = (lle_t **)arg;
	lle_t *entryptr = NULL;
	lle_t *lentryptr = NULL;
	uint64 *tmpsort;
	int	tmpcnt;
	int	tmpsortc;
	int i;

	if (hashptr == NULL) return;

	tmpsortc = hsize * 2;
	tmpsort = malloc(sizeof(lle_t *) * hsize * 2);
	MALLOC_LOG(tmpsort, sizeof(lle_t *) * hsize * 2);
	tmpcnt = 0;

	for (i=0; i < hsize; i++) {
		entryptr = hashptr[i];
		while (entryptr != NULL) {
			if (debug) printf ("[%d] 0x%llx: key 0x%llx\n", i, entryptr, entryptr->key);
			if (debug && (entryptr->key > 0x10000000)) _exit(10);
			if (sort_func && sort_flag) { 
				if (entryptr->key == UNKNOWN_WCHAN)
					/* process last if key is UNKNOWN_WCHAN */
					lentryptr = entryptr;
				else {
					if (tmpcnt == tmpsortc) {
						tmpsortc += hsize*2;
						tmpsort = realloc((uint64 *)tmpsort, sizeof(lle_t *) * tmpsortc);
					}

					*(tmpsort + tmpcnt++) = (uint64)entryptr;
				}
			} else { 
				work_func((void *)entryptr, work_arg);
			}

			entryptr = (void *)entryptr->next;
		}
	}

	if ((sort_func == NULL) || !sort_flag) {
		FREE(tmpsort);
		return;
	}

	if ((tmpcnt > 1) && sort_flag) {
		qsort (tmpsort, tmpcnt, sizeof(lle_t *), sort_func);
	}

	if (tmpcnt > 0) {
		for (i = 0; i < tmpcnt; i++) {
			entryptr = (lle_t *)*(tmpsort + i);

			if ((cnt < 0) && (i < -cnt)) continue;

			work_func((void *)entryptr, work_arg);

			if ((cnt > 0) && ((i+1) == cnt)) i = tmpcnt;
		}
	}

	FREE(tmpsort);

	if (lentryptr) {
		work_func((void *)lentryptr, work_arg);
	}
}

void
foreach_server(int (*work_func)(void *, void *), int (*sort_func)(const void *, const void *), int32 cnt, void *work_arg) 
{
	server_info_t *entryptr;
	uint64 *tmpsort;
	int	tmpcnt;
	int	tmpsortc;
	int i;

	tmpsortc = nservers * 2;
	tmpsort = malloc(sizeof(server_info_t *) * nservers * 2);
	MALLOC_LOG(tmpsort, sizeof(server_info_t *) * nservers * 2);
	tmpcnt = 0;

	for (i=0; i < nservers; i++) {
		if (entryptr = server[i]) {
			if (sort_func && sort_flag) { 
				if (tmpcnt == tmpsortc) {
					tmpsortc += nservers*2;
					tmpsort = realloc((uint64 *)tmpsort, sizeof(lle_t *) * tmpsortc);
				}

				*(tmpsort + tmpcnt++) = (uint64)entryptr;
			} else { 
				globals = entryptr;
				work_func((void *)entryptr, work_arg);
			}
		}
	}

	if ((sort_func == NULL) || !sort_flag) {
		FREE(tmpsort);
		return;
	}

	if ((tmpcnt > 1) && sort_flag) {
		qsort (tmpsort, tmpcnt, sizeof(lle_t *), sort_func);
	}

	if (tmpcnt > 0) {
		for (i = 0; i < tmpcnt; i++) {
			entryptr = (server_info_t *)*(tmpsort + i);
			globals = entryptr;

			if ((cnt < 0) && (i < -cnt)) continue;

			work_func((void *)entryptr, work_arg);

			if ((cnt > 0) && ((i+1) == cnt)) i = tmpcnt;
		}
	}

	FREE(tmpsort);
}


int 
hash_count_entries(void *arg1, void *arg2)
{
	int *cntp = (int *)arg2;
        (*cntp)++;
	return 0;
}




/*
 * Mixing function, use it as a hash
 */
#define mix64(a,b,c) \
{ \
  a=a-b;  a=a-c;  a=a^(c>>43); \
  b=b-c;  b=b-a;  b=b^(a<<9) ; \
  c=c-a;  c=c-b;  c=c^(b>>8) ; \
  a=a-b;  a=a-c;  a=a^(c>>38); \
  b=b-c;  b=b-a;  b=b^(a<<23); \
  c=c-a;  c=c-b;  c=c^(b>>5) ; \
  a=a-b;  a=a-c;  a=a^(c>>35); \
  b=b-c;  b=b-a;  b=b^(a<<49); \
  c=c-a;  c=c-b;  c=c^(b>>11); \
  a=a-b;  a=a-c;  a=a^(c>>12); \
  b=b-c;  b=b-a;  b=b^(a<<18); \
  c=c-a;  c=c-b;  c=c^(b>>22); \
}

uint64
addrHash(uint64 addr )
{
        uint64 hash, b, c;

        // Hash value & Hash step
        hash = addr;
        b = 0X123456789ABCDEF0ULL;
        c = 0x5a5a5a5a5a5a5a5aULL;

        mix64( hash, b, c );

        return hash;

}


/*
 * Hash function
 */
typedef  unsigned int  ub4;   /* unsigned 4-byte quantities */
typedef  unsigned char ub1;   /* unsigned 1-byte quantities */

#define hashsize(n) ((ub4)1<<(n))
#define hashmask(n) (hashsize(n)-1)

/*
--------------------------------------------------------------------
mix -- mix 3 32-bit values reversibly.
For every delta with one or two bits set, and the deltas of all three
  high bits or all three low bits, whether the original value of a,b,c
  is almost all zero or is uniformly distributed,
* If mix() is run forward or backward, at least 32 bits in a,b,c
  have at least 1/4 probability of changing.
* If mix() is run forward, every bit of c will change between 1/3 and
  2/3 of the time.  (Well, 22/100 and 78/100 for some 2-bit deltas.)
mix() takes 36 machine instructions, but only 18 cycles on a superscalar
  machine (like a Pentium or a Sparc).  No faster mixer seems to work,
  that's the result of my brute-force search.  There were about 2^^68
  hashes to choose from.  I only tested about a billion of those.
--------------------------------------------------------------------
*/
#define mix(a,b,c) \
{ \
  a -= b; a -= c; a ^= (c>>13); \
  b -= c; b -= a; b ^= (a<<8); \
  c -= a; c -= b; c ^= (b>>13); \
  a -= b; a -= c; a ^= (c>>12);  \
  b -= c; b -= a; b ^= (a<<16); \
  c -= a; c -= b; c ^= (b>>5); \
  a -= b; a -= c; a ^= (c>>3);  \
  b -= c; b -= a; b ^= (a<<10); \
  c -= a; c -= b; c ^= (b>>15); \
}


/*
--------------------------------------------------------------------
hash() -- hash a variable-length key into a 32-bit value
  k       : the key (the unaligned variable-length array of bytes)
  len     : the length of the key, counting by bytes
  initval : can be any 4-byte value
Returns a 32-bit value.  Every bit of the key affects every bit of
the return value.  Every 1-bit and 2-bit delta achieves avalanche.
About 6*len+35 instructions.

The best hash table sizes are powers of 2.  There is no need to do
mod a prime (mod is sooo slow!).  If you need less than 32 bits,
use a bitmask.  For example, if you need only 10 bits, do
  h = (h & hashmask(10));
In which case, the hash table should have hashsize(10) elements.

If you are hashing n strings (ub1 **)k, do it like this:
  for (i=0, h=0; i<n; ++i) h = hash( k[i], len[i], h);

By Bob Jenkins, 1996.  bob_jenkins@burtleburtle.net.  You may use this
code any way you wish, private, educational, or commercial.  It's free.

See http://burtleburtle.net/bob/hash/evahash.html
Use for hash table lookup, or anything where one collision in 2^^32 is
acceptable.  Do NOT use for cryptographic purposes.
--------------------------------------------------------------------
*/

uint64
doobsHash( void *arg,      /* the key */
           uint32 length,  /* the length of the key */
           uint32 initval) /* the previous hash, or an arbitrary value */
{
   register uint32 a,b,len;
   ub1 *k = (ub1 *)arg;
   uint64 c;

   /* Set up the internal state */
   len = length;
   a = b = 0x9e3779b9;  /* the golden ratio; an arbitrary value */
   c = initval;         /* the previous hash value */

   /*---------------------------------------- handle most of the key */
   while (len >= 12)
   {
      a += (k[0] +((ub4)k[1]<<8) +((ub4)k[2]<<16) +((ub4)k[3]<<24));
      b += (k[4] +((ub4)k[5]<<8) +((ub4)k[6]<<16) +((ub4)k[7]<<24));
      c += (k[8] +((ub4)k[9]<<8) +((ub4)k[10]<<16)+((ub4)k[11]<<24));
      mix(a,b,c);
      k += 12; len -= 12;
   }

   /*------------------------------------- handle the last 11 bytes */
   c += length;
   switch(len)              /* all the case statements fall through */
   {
   case 11: c+=((ub4)k[10]<<24);
   case 10: c+=((ub4)k[9]<<16);
   case 9 : c+=((ub4)k[8]<<8);
      /* the first byte of c is reserved for the length */
   case 8 : b+=((ub4)k[7]<<24);
   case 7 : b+=((ub4)k[6]<<16);
   case 6 : b+=((ub4)k[5]<<8);
   case 5 : b+=k[4];
   case 4 : a+=((ub4)k[3]<<24);
   case 3 : a+=((ub4)k[2]<<16);
   case 2 : a+=((ub4)k[1]<<8);
   case 1 : a+=k[0];
     /* case 0: nothing left to add */
   }
   mix(a,b,c);
   /*-------------------------------------------- report the result */
   return c;
}

/*
**  similar to find_add_hash_entry, but for doubly linked lists 
*/
lle_t *
find_remove_hash_entry (lle_t ***hashaddr, int hashsz, uint64 key, int idx, int size)
{
lle_t **hashptr;
lle_t *prevptr, *entryptr;

	hashptr = *hashaddr;
	if ((idx < 0) || idx > (hashsz)) {
		fprintf (stderr, "Suspect hash index passed to find_add_hash_entry\n");
		fprintf (stderr, "find_add_hash_entry(hashptr: 0x%llx, hashsz %d, key: 0x%llx idx: 0x%x (%d), size %d)\n", hashptr, hashsz, key, idx, idx, size);  
		FATAL(3201, "Invalid hash index", "idx:", idx);
	}

	if (hashptr == NULL) {
		return(NULL);
	}

	prevptr = (lle_t *)&hashptr[idx];
	entryptr = (lle_t *)hashptr[idx];
	while (entryptr != NULL) {
		if (entryptr->key == key)  {
			prevptr->next = entryptr->next;
			return entryptr;
		}
		prevptr = entryptr;
		entryptr = entryptr->next;
	}

	return(NULL);
}


void
free_hash_chain(lle_t *ptr)
{
	lle_t	*nextptr;

	while (ptr != NULL) {
		nextptr = ptr->next;
		FREE(ptr);
		ptr = nextptr;
	}
}

void 
free_hash_table(lle_t ***hashaddr, int hashsz)
{
	lle_t **hashptr;
	lle_t *entryptr;
	int idx;
	
	hashptr = *hashaddr;
	if (hashptr == NULL) return;

	for (idx = 0; idx < hashsz; idx++) {
		entryptr = (lle_t *)hashptr[idx];
		free_hash_chain(entryptr);
	}

	FREE(hashptr);
	*hashaddr = NULL;
}

