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
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <sys/mman.h>
#include <sys/errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "ki_tool.h"
#include "liki.h"
#include "winki.h"
#include "developers.h"
#include "kd_types.h"
#include "globals.h"
#include "info.h"
#include "hash.h"
#include "sort.h"
#include "Provider.h"

#define BUFSZ 0x400ull
#define BUF_ALIGN_MASK ~(BUFSZ-1)
#define VALID_LEN(len)  ((len < 0x1000) && (len > 8))

static FILE *pdb_file = NULL;

typedef struct SymHeader {
	uint32 Value;
} SymHeader_t;

typedef struct SymEntryRec {
	uint16 RecLen;
	uint16 Type;
	uint32 reserved1;
	uint32 NextOffset;
	uint32 reserved2;
	uint32 Number;
	uint32 reserved3[3];
	uint32 Addr;
	uint16 reserved4;
	char   Name[];
} SymEntryRec_t;

typedef struct SymEntryRec_110e {
	uint16 RecLen;
	uint16 Type;
	uint32 reserved1;
	uint32 Addr;
	uint16 reserved2;
	char   Name[];
} SymEntryRec_110e_t;


int
bsearch_pdb_symtab(uint64 ip, pdb_symidx_t *symtab, int nsyms  )
{
	int high, low, mid;
	uint32 found_idx;
	uint64 tmpptr;	

	if (debug) printf (" addr: 0x%llx nsyms=%d low=0x%llx high=0x%llx ", ip, nsyms, symtab[0].symaddr, symtab[nsyms-1].symaddr);
	if (ip > symtab[nsyms-1].symaddr) return -1;
	if (ip < symtab[0].symaddr) return -1;

	low = 0;
	high = nsyms - 1;
	while (1) {
		if ((high - low) <= 1) {
			if (debug) printf (" found=0x%llx %s ", symtab[low].symaddr, symtab[low].symptr);
			return low;
		}
		mid = (low + high) / 2;
		tmpptr = symtab[mid].symaddr;
	
		if (ip < tmpptr) {
			high = mid;
		} else {
			low = mid;
		}
	}

	if (debug) printf (" found=0x%llx %s\n", symtab[low].symaddr, symtab[low].symptr);
	return low;
}

static	char		*ntkrnlmp_pdb = "ntkrnlmp.pdb";
static	char 		*kernelbase_pdb = "kernelbase.pdb";
static	char 		*sqldk_pdb = "SqlDK.pdb";
static  char		*sqltses_pdb = "SqlTsEs.pdb";
static	char 		*ntfs_pdb = "ntfs.pdb";
static	char 		*fltmgr_pdb = "fltMgr.pdb";
static  char		*msvcr120_pdb = "msvcr120.amd64.pdb";

char *
win_symlookup(vtxt_preg_t *pregp, uint64 ip, uint64 *symaddr)
{

	pdb_symidx_t 	*symtab = NULL;
	char		*pdbname;
	char 		*ptr;
	char		*symptr;
	uint64		offset;	
	int		symtab_idx;
	uint64		key;
	pdb_info_t	*pdbinfop;

	if (pregp == NULL) return NULL;

	if (debug) printf (" win_symlookup 0x%llx vaddr=0x%llx", ip, pregp->p_vaddr);

	if (pregp->symbols) {
		symtab = (pdb_symidx_t *)pregp->symbols;
	} else {
		/* need to find symtab from the  pdbinfo 
		   The pregp->filename is the name of the .dll, .exe, or .sys.   
		   So need to convert to PDB name.
		*/
		if (strncmp(pregp->filename, "ntoskrnl.exe", strlen("ntoskrnl.exe")) == 0) {
			pdbname = ntkrnlmp_pdb;
		} else if (strncmp(pregp->filename, "KernelBase.dll", strlen("KernelBase.dll")) == 0) {
			pdbname = kernelbase_pdb;
		} else if (strncmp(pregp->filename, "sqldk.dll", strlen("sqldk.dll")) == 0) {
			pdbname = sqldk_pdb;
		} else if (strncmp(pregp->filename, "sqltses.dll", strlen("sqltses.dll")) == 0) {
			pdbname = sqltses_pdb;
		} else if (strncmp(pregp->filename, "NTFS.sys", strlen("Ntfs.sys")) == 0) {
			pdbname = ntfs_pdb;
		} else if (strncmp(pregp->filename, "Ntfs.sys", strlen("Ntfs.sys")) == 0) {
			pdbname = ntfs_pdb;
		} else if (strncmp(pregp->filename, "FLTMGR.SYS", strlen("FLTMGR.SYS")) == 0) {
			pdbname = fltmgr_pdb;
                } else if (strncmp(pregp->filename, "msvcr120.dll", strlen("msvcr120.dll")) == 0) {
                        pdbname = msvcr120_pdb;

		} else {
			sprintf (util_str, pregp->filename);
			pdbname = &util_str[0];
			ptr = strrchr(pdbname, '.');
			if (ptr) {
				ptr[1]= 'p';
				ptr[2]= 'd';
				ptr[3]= 'b';
			}
		}

		key = doobsHash(&pdbname[0], strlen(pdbname), 0xff);
		pdbinfop = (pdb_info_t *)find_add_strhash_entry((strlle_t ***)&globals->pdbmap_hash, PDB_HSIZE, PDB_HASH(key), sizeof(pdb_info_t), &pdbname[0], strlen(pdbname));
		symtab = pdbinfop->symtab;
		if (pregp->symbols == NULL ) {
			pregp->symbols = pdbinfop->symtab;
			pregp->nsyms = pdbinfop->nsyms;
		}
	}

	if (symtab == NULL) return NULL;

	symtab_idx = bsearch_pdb_symtab(ip - (pregp->p_vaddr), symtab, pregp->nsyms);

	if (symtab_idx >= 0) {	
		*symaddr = symtab[symtab_idx].symaddr;
		symptr = symtab[symtab_idx].symptr;	
	} else { 
		symptr = NULL;
	}

	return symptr;	

}

vtxt_preg_t *
get_win_pregp(unsigned long ip, pid_info_t *pidp)
{
	vtxt_preg_t *pregp = NULL;

	if (WINKERN_ADDR(ip)) {
		pregp = find_vtext_preg(globals->vtxt_pregp, ip);	
	} else if (pidp == NULL) {
		pregp = NULL;
	} else {
		if ((pidp->tgid) && (pidp->PID != pidp->tgid)) {
			pidp = GET_PIDP(&globals->pid_hash, pidp->tgid);
		}
		pregp = find_vtext_preg(pidp->vtxt_pregp, ip); 
	}

	return pregp;
}

char *
get_win_sym(unsigned long ip, pid_info_t *pidp) 
{
	uint64 offset;
	uint64 symaddr;
	vtxt_preg_t *pregp;
	char *symptr=NULL;
	char *symaddr_str;

	if (ip == 0x0) return 0;
	/* printf ("0x%llx ", ip); return 0; */

	pregp = get_win_pregp(ip, pidp);
	if (pregp) {
		symptr = win_symlookup(pregp, ip, &symaddr);
	}

	return symptr;
}

int
print_win_sym(unsigned long ip, pid_info_t *pidp) 
{
	uint64 offset;
	uint64 symaddr = 0ull;
	vtxt_preg_t *pregp;
	char *symptr=NULL;

	if (ip == 0x0) return 0;
	/* printf ("0x%llx ", ip); return 0; */

	if (pregp = get_win_pregp(ip, pidp)) {
		if (symptr = win_symlookup(pregp, ip, &symaddr)) {
			printf ("%s?%s+0x%llx ", pregp->filename, symptr, (ip - pregp->p_vaddr) - symaddr);
			/* printf ("%s?%s+0x%x (0x%llx) ", pregp->filename, symptr, (ip - pregp->p_vaddr) - symaddr, ip); */
		} else if (pregp->filename) {
			printf ("%s?0x%llx ", pregp->filename, ip);
		} else {
			printf ("0x%llx ", ip);
		}
	} else {
		printf ("0x%llx ", ip);
	}
}

	
int pdb_symidx_sort_func(const void *v1, const void *v2)
{
        const pdb_symidx_t *a1 = (pdb_symidx_t *)v1;
        const pdb_symidx_t *a2 = (pdb_symidx_t *)v2;
        int64 diff;

        diff = a2->symaddr - a1->symaddr;

        if (diff < 0) {
                return 1;
        } else if (diff > 0) {
                return -1;
        } else {
                return 0;
        }
}



static inline int
valid_symrec(char *ptr)
{
	SymEntryRec_t *symrecp = (SymEntryRec_t *)ptr;

	if (!VALID_LEN(symrecp->RecLen)) return 0;

	switch(symrecp->Type) {
		case 0x110f:
		case 0x1019:
		case 0x1110:
		case 0x110e:
		case 0x1125:
		case 0x1127:
		case 0x1128:
		case 0x1132:
			return 1;
		default: return 0; 
	}
}	

static inline int
splice_rec(pdb_symidx_t *symtab, SymEntryRec_t *symrecp, char *buf, uint64 offset)
{
	SymEntryRec_110e_t *symrec_110e_p;
	char *ptr;

	printf ("splice_rec: 0x%llx 0x%llx 0x%llx\n", symrecp, buf, offset);	
	if ((ptr = malloc (symrecp->RecLen)) == NULL) {
		fprintf (stderr, "splice_rec: failed to malloc() %d bytes\n", symrecp->RecLen);
		return 0;
	} else { 
		memcpy(ptr, symrecp, symrecp->RecLen - offset);
		memcpy(ptr, buf, offset);

		symrecp = (SymEntryRec_t *)ptr;
		symrec_110e_p = (SymEntryRec_110e_t *)ptr;
		switch(symrecp->Type) {
			case 0x110f:
			case 0x1110:
				symtab->symaddr = symrecp->Addr + 0x1000;
				symtab->symptr = &symrecp->Name[1];
				break;
			case 0x110e:
				symtab->symaddr = symrec_110e_p->Addr + 0x1000;
				symtab->symptr = &symrec_110e_p->Name[0];
				break;
		default: ;
		}
	}
} 

int
build_symbol_table(char *pdbname) 
{
	int pdb_fd, i;
	struct stat statbuf;
	uint64 offset = 0, addr, size, len=0;
	char *mapptr, *buf, *ptr;
	SymEntryRec_t *symrecp;
	SymEntryRec_110e_t *symrec_110e_p;
	SymHeader_t *symhdrp;
	uint32	*value;
	int ret, nsyms=0;
	pdb_info_t *pdbinfop;
	uint64 key;

	key = doobsHash(&pdbname[0], strlen(pdbname), 0xff);
	pdbinfop = (pdb_info_t *)find_add_strhash_entry((strlle_t ***)&globals->pdbmap_hash, PDB_HSIZE, PDB_HASH(key), sizeof(pdb_info_t), &pdbname[0], strlen(pdbname));

	if (pdbinfop->symtab) {
		/* Symbol table is already built! */
		return 0;
	}

	add_string(&pdbinfop->filename, pdbname);
	/* printf ("build_symbol_table: pdbinfop: 0x%llx  %s  \n", pdbinfop, pdbinfop->filename); */

	if ((pdb_fd = open(pdbname, O_RDONLY)) < 0)  {
		fprintf(stderr, "Unable to open PDB file %s for processing\n", pdbname);
		perror("open error");
		return 0;
	}

	if ((ret = fstat(pdb_fd, &statbuf)) < 0) {
		fprintf(stderr, "Unable to stat PDB file %s for processing\n", pdbname);
		perror("fstat error");
                close(pdb_fd);
                return 0;
        }

	if ((size = statbuf.st_size) == 0) {
		fprintf(stderr, "PDB file %s is empty\n", pdbname);
                close(pdb_fd);
                return 0;
        }

	size = statbuf.st_size;
	mapptr = mmap(NULL, size, PROT_READ, MAP_PRIVATE, pdb_fd, 0);
	if (mapptr == MAP_FAILED) {
		fprintf(stderr, "Unable to mmap PDB file %s for processing\n", pdbname);
		close(pdb_fd);
		return 0;
	}

	close (pdb_fd);

	pdbinfop->mapptr = mapptr;
	pdbinfop->size = size;
	/* should match lle.key */
	/* add_string(&pdbinfop->name, pdbname);	*/

	buf = mapptr+BUFSZ;
	i = 0;

	while (buf < ((mapptr+size) - BUFSZ)) {
		symhdrp = (SymHeader_t *)buf;

		if (symhdrp->Value != 4) {
			if (valid_symrec((char *)symhdrp)) {
				symrecp = (SymEntryRec_t *)symhdrp;
			} else {
				buf = buf + BUFSZ;
				continue;
			}
		} else {
			symrecp = (SymEntryRec_t *)(buf + sizeof(SymHeader_t));
		}

		while (((char *)symrecp < (mapptr+size)) &&(symrecp->Type != 0) && valid_symrec((char *)symrecp)) {
			symrec_110e_p = (SymEntryRec_110e_t *)symrecp;
			switch(symrecp->Type) {
				case 0x110f:
				case 0x1110:
					printf ("[%d] 0x%llx 0x%04x:   %08x  %4d   +0x%03x  %s  \n", i, (char *)symrecp - mapptr, symrecp->Type, symrecp->Addr, symrecp->Number, symrecp->RecLen, &symrecp->Name[1]);
					i++;
					break;
				case 0x110e:
					printf ("[%d] 0x%llx 0x%04x: %8x +0x%03x  %s  \n", i, (char *)symrec_110e_p - mapptr, symrec_110e_p->Type, symrec_110e_p->Addr, symrec_110e_p->RecLen, &symrec_110e_p->Name[0]);
					i++;
					break;
				case 0x1019:
				case 0x1125:
				case 0x1127:
				case 0x1128:
					printf ("[%d] 0x%llx 0x%04x: %8x  +0x%03x  %s  \n", i, (char *)symrec_110e_p - mapptr, symrec_110e_p->Type, symrec_110e_p->Addr, symrec_110e_p->RecLen, &symrec_110e_p->Name[0]);
					break;
				case 0x1132:
					printf ("[%d] 0x%llx 0x%04x: +0x%x\n", i, (char *)symrecp - mapptr, symrecp->Type, symrecp->RecLen);
					break;
				default:  
					printf ("[%d] 0x%llx: Type:  0x%04x +0x%x  Unknown Rec\n", i, (char *)symrecp - mapptr, symrecp->Type, symrecp->RecLen);
					break;
					
			}

			ptr = ((char *)symrecp) + ((symrecp->RecLen + 3) & ~0x3);     
			symhdrp = (SymHeader_t *)ptr; 

			/* We do have to check for breaks in the symbol table in the PDB file
			   as its not sequential 1K bufers. First we check to see  if we have
                           crossed a buffer boundary, and it so see if its OK   */

			if (((uint64)symrecp & BUF_ALIGN_MASK) != ((uint64)ptr & BUF_ALIGN_MASK)) {
				/* OK we crossed a buffer, maybe 2.  Check to see if the next record looks OK */
				printf ("Crossing buffer \n");
				/* check for end of buffer at the Start of the buffer! */
				value = &symhdrp->Value;
				if ((value[0] == 0x0) && (value[1]==0x0) && (value[-1] != 0x0)) { 
						/* Were Cool!, move to next buffer */ 
						symrecp = (SymEntryRec_t *)symhdrp;
				} else if ((symhdrp->Value == 0x60002) && (valid_symrec(ptr + sizeof(SymHeader_t)))) {
					symrecp = (SymEntryRec_t *)(ptr + sizeof(SymHeader_t));
				} else if (valid_symrec(ptr)) {
					symrecp = (SymEntryRec_t *)ptr;
				} else { 
					/* this is the hard part.   Need to scan for the buffers to
					   see when the symbol table resumes.  */
					printf ("Scanning buffers starting at 0x%llx\n", mapptr - buf);
					buf = (char *)((uint64)ptr & BUF_ALIGN_MASK);
					offset = ptr - buf;

					while (buf < ((mapptr+size) - BUFSZ)) {

						ptr = buf + offset;
						if ((symhdrp->Value == 0x60002) && (valid_symrec(ptr + sizeof(SymHeader_t)))) {
							symrecp = (SymEntryRec_t *)(ptr + sizeof(SymHeader_t));
							break;
						} else if (valid_symrec(ptr)) {
							symrecp = (SymEntryRec_t *)ptr;
							break;
						} 

						buf += BUFSZ;
						/* check next buffer */
					}
				}
			} else {
				/* In the same buffer, go to next rec */
				if (symhdrp->Value < 8) break;

				if (symhdrp->Value == 0x60002) {
					symrecp = (SymEntryRec_t *)(ptr + sizeof(SymHeader_t));
				} else {
					symrecp = (SymEntryRec_t *)(ptr);
				}
				
				if (symrecp->RecLen < 8) break;
			}
		}
			
		printf ("0x%llx: Type: 0x%04x 0x%x  END\n", (char *)symrecp-mapptr, symrecp->Type, symrecp->RecLen); 
		
		/* Advance to next 1K block */	
		buf = (char *)(((uint64)symrecp + BUFSZ) & BUF_ALIGN_MASK);
		
	}


	nsyms = i;
	if (pdbinfop->symtab = malloc(nsyms*sizeof(pdb_symidx_t))) {
                MALLOC_LOG(pdbinfop->symtab, nsyms*sizeof(pdb_symidx_t));
	} else { 
		fprintf (stderr, "Unable to Malloc symtab file for %s - nsyms = %d\n", pdbname, nsyms);
		munmap(mapptr, size);
		return 0;
	}

	pdbinfop->nsyms = nsyms;

	buf = mapptr+BUFSZ;
	i = 0;

	while (buf < ((mapptr+size) - BUFSZ)) {
		symhdrp = (SymHeader_t *)buf;

		if (symhdrp->Value != 4) {
			if (valid_symrec((char *)symhdrp)) {
				symrecp = (SymEntryRec_t *)symhdrp;
			} else {
				buf = buf + BUFSZ;
				continue;
			}
		} else {
			symrecp = (SymEntryRec_t *)(buf + sizeof(SymHeader_t));
		}

		while ((symrecp->Type != 0) && valid_symrec((char *)symrecp)) {
			symrec_110e_p = (SymEntryRec_110e_t *)symrecp;
			switch(symrecp->Type) {
				case 0x110f:
				case 0x1110:
					pdbinfop->symtab[i].symaddr = symrecp->Addr + 0x1000;
					pdbinfop->symtab[i].symptr = &symrecp->Name[1];
					printf ("[%d] 0x%llx 0x%04x:   %08x  %4d   +0x%03x  %s  \n", i, (char *)symrecp - mapptr, symrecp->Type, symrecp->Addr, symrecp->Number, symrecp->RecLen, &symrecp->Name[1]);
					i++;
					break;
				case 0x110e:
					pdbinfop->symtab[i].symaddr = symrec_110e_p->Addr + 0x1000;
					pdbinfop->symtab[i].symptr = &symrec_110e_p->Name[0];
					printf ("[%d] 0x%llx 0x%04x: %8x +0x%03x  %s  \n", i, (char *)symrec_110e_p - mapptr, symrec_110e_p->Type, symrec_110e_p->Addr, symrec_110e_p->RecLen, &symrec_110e_p->Name[0]);
					i++;
					break;
				case 0x1019:
				case 0x1125:
				case 0x1127:
				case 0x1128:
					printf ("[%d] 0x%llx 0x%04x: %8x  +0x%03x  %s  \n", i, (char *)symrec_110e_p - mapptr, symrec_110e_p->Type, symrec_110e_p->Addr, symrec_110e_p->RecLen, &symrec_110e_p->Name[0]);
					break;
				case 0x1132:
					printf ("[%d] 0x%llx 0x%04x: +0x%x\n", i, (char *)symrecp - mapptr, symrecp->Type, symrecp->RecLen);
					break;
				default:  
					printf ("[%d] 0x%llx: Type:  0x%04x +0x%x  Unknown Rec\n", i, (char *)symrecp - mapptr, symrecp->Type, symrecp->RecLen);
					break;
					
			}

			ptr = ((char *)symrecp) + ((symrecp->RecLen + 3) & ~0x3);     
			symhdrp = (SymHeader_t *)ptr; 

			/* We do have to check for breaks in the symbol table in the PDB file
			   as its not sequential 1K bufers. First we check to see  if we have
                           crossed a buffer boundary, and it so see if its OK   */

			if (((uint64)symrecp & BUF_ALIGN_MASK) != ((uint64)ptr & BUF_ALIGN_MASK)) {
				/* OK we crossed a buffer, maybe 2.  Check to see if the next record looks OK */
				printf ("Crossing buffer \n");
				/* check for end of buffer at the Start of the buffer! */
				value = &symhdrp->Value;
				if ((value[0] == 0x0) && (value[1]==0x0) && (value[-1] != 0x0)) { 
						/* Were Cool!, move to next buffer */ 
						symrecp = (SymEntryRec_t *)symhdrp;
				} else if ((symhdrp->Value == 0x60002) && (valid_symrec(ptr + sizeof(SymHeader_t)))) {
					symrecp = (SymEntryRec_t *)(ptr + sizeof(SymHeader_t));
				} else if (valid_symrec(ptr)) {
					symrecp = (SymEntryRec_t *)ptr;
				} else { 
					/* this is the hard part.   Need to scan for the buffers to
					   see when the symbol table resumes.  */
					printf ("Scanning buffers starting at 0x%llx\n", mapptr - buf);
					buf = (char *)((uint64)ptr & BUF_ALIGN_MASK);
					offset = ptr - buf;

					while (buf < ((mapptr+size) - BUFSZ)) {

						ptr = buf + offset;
						if ((symhdrp->Value == 0x60002) && (valid_symrec(ptr + sizeof(SymHeader_t)))) {
							splice_rec(&pdbinfop->symtab[i], symrecp, buf, offset);
							symrecp = (SymEntryRec_t *)(ptr + sizeof(SymHeader_t));
							break;
						} else if (valid_symrec(ptr)) {
							splice_rec(&pdbinfop->symtab[i], symrecp, buf, offset);
							symrecp = (SymEntryRec_t *)ptr;
							break;
						} 

						buf += BUFSZ;
						/* check next buffer */
					}
				}
			} else {
				/* In the same buffer, go to next rec */
				if (symhdrp->Value < 8) break;

				if (symhdrp->Value == 0x60002) {
					symrecp = (SymEntryRec_t *)(ptr + sizeof(SymHeader_t));
				} else {
					symrecp = (SymEntryRec_t *)(ptr);
				}
				
				if (symrecp->RecLen < 8) break;
			}
		}
			
		printf ("0x%llx: Type: 0x%04x 0x%x  END\n", (char *)symrecp-mapptr, symrecp->Type, symrecp->RecLen); 
		
		/* Advance to next 1K block */	
		buf = (char *)(((uint64)symrecp + BUFSZ) & BUF_ALIGN_MASK);
		
	}

	if (i != nsyms) fprintf (stderr, "%s Unexpected number of symbols found: %d, expected %d\n", pdbname, i, nsyms);

        qsort(&pdbinfop->symtab[0], nsyms, sizeof(pdb_symidx_t), pdb_symidx_sort_func);

	printf (" symtab: 0x%llx\n", pdbinfop->symtab);

	printf ("\nDumping Function Symbols for %s mapped at address 0x%llx (nsyms=%d)\n", pdbname, mapptr, nsyms);
	for (i = 0; i < nsyms; i++) {
		printf ("[%6d] %08x  %s\n", i, pdbinfop->symtab[i].symaddr, pdbinfop->symtab[i].symptr);
	}
}

int filter_pdb(char *name) 
{
	int ret=1;
	char *rtnptr;
	
	if (strcasestr(name, "ntkrnlmp.pdb") == name) return 1;
	else if (strcasestr(name, "ntdll.pdb") == name) return 1;
	else if (strcasestr(name, "kernelbase.pdb") == name) return 1;
	else if (strcasestr(name, "SqlDK.pdb") == name) return 1;
	else if (strcasestr(name, "sqlmin.pdb") == name) return 1;
	else if (strcasestr(name, "sqllang.pdb") == name) return 1;
	else if (strcasestr(name, "sqltses.pdb") == name) return 1;
	else if (strcasestr(name, "ucrtbase.pdb") == name) return 1;
	else if (strcasestr(name, "rdpserverbase.pdb") == name) return 1;
	else if (strcasestr(name, "rdpbase.pdb") == name) return 1;
	else if (strcasestr(name, "tcpip.pdb") == name) return 1;
	else if (strcasestr(name, "partmgr.pdb") == name) return 1;
	else if (strcasestr(name, "ntfs.pdb") == name) return 1;
	else if (strcasestr(name, "fltmgr.pdb") == name) return 1;
	else if (strcasestr(name, "fileinfo.pdb") == name) return 1;
	else if (strcasestr(name, "hal.pdb") == name) return 1;
	else if (strcasestr(name, "vmbus.pdb") == name) return 1;
	else if (strcasestr(name, "vmbkmcl.pdb") == name) return 1;
	else if (strcasestr(name, "storport.pdb") == name) return 1;
	else if (strcasestr(name, "mswsock.pdb") == name) return 1;
	else if (strcasestr(name, "wow64cpu.pdb") == name) return 1;
	else if (strcasestr(name, "qds.pdb") == name) return 1;
	else if (strcasestr(name, "afd.pdb") == name) return 1;
	else if (strcasestr(name, "clr.pdb") == name) return 1;
	else if (strcasestr(name, "msvcr120.amd64.pdb") == name) return 1;
	else if (strcasestr(name, "kernel32.pdb") == name) return 1;
        else if (strcasestr(name, "user32.pdb") == name) return 1;
        else if (strcasestr(name, "win32u.pdb") == name) return 1;
        else if (strcasestr(name, "win32k.pdb") == name) return 1;
	else if (strcasestr(name, "win32kfull.pdb") == name) return 1;
        else if (strcasestr(name, "rdsdwmdr.pdb") == name) return 1;
        else if (strcasestr(name, "dwmredir.pdb") == name) return 1;
        else if (strcasestr(name, "dwmcore.pdb") == name) return 1;
	else if (strcasestr(name, "intelppm.pdb") == name) return 1;

	if (pdbfiles == NULL) return 0;
	
	if (pdb_file == NULL) {  
		if ((pdb_file = fopen(pdbfiles, "r")) == NULL) {
			if (debug) fprintf (stderr, "Unlable to open file %s, errno %d\n");
			return 0;
		}
	}

	fseek(pdb_file, 0, SEEK_SET);

	while (rtnptr == fgets((char *)&input_str, 511, pdb_file)) {
		if (strcasestr(name, rtnptr) == name) return 1;
	}
	

	return 0;
}
	

int
build_symbol_table_from_txt(char *pdbname, char *txtname) 
{
	FILE *txtfile;
	int i=0;
	struct stat statbuf;
	uint64 offset = 0, addr, size, len=0;
	char *rtnptr;
	uint32	*value, tmp;
	int ret, nsyms=0;
	pdb_info_t *pdbinfop;
	uint64 key;
	char tag[128], symbol[2048];


	key = doobsHash(&pdbname[0], strlen(pdbname), 0xff);
	pdbinfop = (pdb_info_t *)find_add_strhash_entry((strlle_t ***)&globals->pdbmap_hash, PDB_HSIZE, PDB_HASH(key), sizeof(pdb_info_t), &pdbname[0], strlen(pdbname));

	if (pdbinfop->symtab) {
		/* Symbol table is already built! */
		return 0;
	}

	/* fprintf (stderr, "build_symbol_table_from_txt():  PDB file: %s  -> TXT file: %s \n", pdbname, txtname); */
	add_string(&pdbinfop->filename, pdbname);

	if ( (txtfile = fopen(txtname, "r")) == NULL) {
		fprintf(stderr, "Unable to open PDB TXT file %s for processing\n", txtname);
		perror("open error");
		return 0;
	}

	rtnptr = fgets((char *)&util_str, 4095, txtfile);
	while (rtnptr != NULL) {
		sscanf (util_str, "%llx %d %s %s\n", &addr, &tmp, tag, symbol);
		if (strstr(tag, "SymTag") && (addr > 0x400000)) i++;
		rtnptr = fgets((char *)&util_str, 4095, txtfile);
	}
		
	nsyms = i;

	if (pdbinfop->symtab = calloc(nsyms,sizeof(pdb_symidx_t))) {
                MALLOC_LOG(pdbinfop->symtab, nsyms*sizeof(pdb_symidx_t));
	} else { 
		fprintf (stderr, "Unable to Malloc symtab file for %s - nsyms = %d\n", pdbname, nsyms);
		fclose(txtfile);
		return 0;
	}

	pdbinfop->nsyms = nsyms;
	if (debug) printf ("nsyms=%d\n", nsyms);

	/* 2nd pass is to build the symbol table */
	rewind(txtfile);
	i = 0;

	rtnptr = fgets((char *)&util_str, 4095, txtfile);
	while (rtnptr != NULL) {
		sscanf (util_str, "%llx %d %s %s\n", &addr, &tmp, tag, symbol);
		/*  if (i > (nsyms-10))  printf ("addr: 0x%llx tag: %s symbol: %s\n", addr, tag, symbol); */

		if (strstr(tag, "SymTag") && (addr > 0x400000)) {
			pdbinfop->symtab[i].symaddr = addr - 0x400000;
			add_string(&pdbinfop->symtab[i].symptr, symbol);
			i++;
		}
		rtnptr = fgets((char *)&util_str, 4095, txtfile);
	}

	if (i != nsyms) fprintf (stderr, "File %s Unexpected number of symbols found: %d, expected %d\n", txtname, i, nsyms);

	/* printf ("Calling qsort for %s with %d symbols\n", pdbname, nsyms); */
        qsort(&pdbinfop->symtab[0], nsyms, sizeof(pdb_symidx_t), pdb_symidx_sort_func);
#if 0
	printf ("\nDumping Function Symbols for %s (nsyms=%d)\n", pdbname, nsyms);
	for (i = 0; i < nsyms; i++) {
		printf ("[%6d] %08x  %s\n", i, pdbinfop->symtab[i].symaddr, pdbinfop->symtab[i].symptr); 
	}
#endif 
	fclose(txtfile);
	return 0;
}

int
build_symbol_table_from_txt2(char *pdbname, char *txtname) 
{
	int txt_fd, i=0;
	struct stat statbuf;
	uint64 offset = 0, addr, size, len=0;
	char *mapptr, *buf, *ptr, *chr;
	uint32	*value, tmp;
	int ret, nsyms=0;
	pdb_info_t *pdbinfop;
	uint64 key;
	char tag[128], symbol[2048];


	key = doobsHash(&pdbname[0], strlen(pdbname), 0xff);
	pdbinfop = (pdb_info_t *)find_add_strhash_entry((strlle_t ***)&globals->pdbmap_hash, PDB_HSIZE, PDB_HASH(key), sizeof(pdb_info_t), &pdbname[0], strlen(pdbname));

	if (pdbinfop->symtab) {
		/* Symbol table is already built! */
		return 0;
	}

	/* printf ("build_symbol_table_from_txt():  PDB file: %s  -> TXT file: %s \n", pdbname, txtname); */
	add_string(&pdbinfop->filename, pdbname);

	if ((txt_fd = open(txtname, O_RDONLY)) < 0)  {
		fprintf(stderr, "Unable to open PDB TXT file %s for processing\n", txtname);
		perror("open error");
		return 0;
	}

	if ((ret = fstat(txt_fd, &statbuf)) < 0) {
		fprintf(stderr, "Unable to stat PDB TXT file %s for processing\n", txtname);
		perror("fstat error");
                close(txt_fd);
                return 0;
        }

	if ((size = statbuf.st_size) == 0) {
		fprintf(stderr, "PDB TXT file %s is empty\n", txtname);
                close(txt_fd);
                return 0;
        }

	size = statbuf.st_size;
	mapptr = mmap(NULL, size, PROT_READ, MAP_PRIVATE, txt_fd, 0);
	if (mapptr == MAP_FAILED) {
		fprintf(stderr, "Unable to mmap PDB TXT file %s for processing\n", txtname);
		close(txt_fd);
		return 0;
	}

	close (txt_fd);

	if ((mapptr[0] != (char)0xff) || (mapptr[1] != (char)0xfe)) { 
		fprintf (stderr, "Invalid PDB TXT file %s, skipping\n", txtname);
		return 0;	
	}

	/* First pass is to count symbols */
	chr = mapptr+2;
	while (chr < mapptr + (size-20)) {
		GET_WIN_LINE(util_str, chr)
		if (strstr(util_str, "SymTag")) i++;
	};

	nsyms = i;
	if (pdbinfop->symtab = calloc(nsyms,sizeof(pdb_symidx_t))) {
                MALLOC_LOG(pdbinfop->symtab, nsyms*sizeof(pdb_symidx_t));
	} else { 
		fprintf (stderr, "Unable to Malloc symtab file for %s - nsyms = %d\n", pdbname, nsyms);
		munmap(mapptr, size);
		return 0;
	}

	pdbinfop->nsyms = nsyms;
	if (debug) printf ("nsyms=%d\n", nsyms);

	/* 2nd pass is to build the symbol table */
	i = 0;
	chr = mapptr+2;
	while (chr < mapptr + (size-20)) {
		GET_WIN_LINE(util_str, chr)

		sscanf (util_str, "%llx %d %s %s\n", &addr, &tmp, tag, symbol);
		/*  if (i > (nsyms-10))  printf ("addr: 0x%llx tag: %s symbol: %s\n", addr, tag, symbol); */

		if (strstr(tag, "SymTag")) {
			pdbinfop->symtab[i].symaddr = addr - 0x400000;
			add_string(&pdbinfop->symtab[i].symptr, symbol);
			i++;
		};
			
	};

	if (i != nsyms) fprintf (stderr, "File %s Unexpected number of symbols found: %d, expected %d\n", txtname, i, nsyms);

	/* printf ("Calling qsort for %s with %d symbols\n", pdbname, nsyms); */
        qsort(&pdbinfop->symtab[0], nsyms, sizeof(pdb_symidx_t), pdb_symidx_sort_func);
#if 0
	printf ("\nDumping Function Symbols for %s mapped at address 0x%llx (nsyms=%d)\n", pdbname, mapptr, nsyms);
	for (i = 0; i < nsyms; i++) {
		printf ("[%6d] %08x  %s\n", i, pdbinfop->symtab[i].symaddr, pdbinfop->symtab[i].symptr); 
	}
#endif
}

static int get_pdb_count = 0;
static int wget_fail_cnt = 0;

int get_pdb(PdbImage_t *p) 
{

	char *name, *ptr, *txtname;
	char wget_str[512];
	struct stat statbuf;
	int result, ret;

	if (wget_fail_cnt > 0) return 0;

        name = &p->Name[0];
	
        if (ptr = strrchr(name, '\\')) {
                name = ++ptr;
        }

	if (strncmp(&name[0], "sqldk.pdb", strlen("sqldk.pdb")) == 0) {
		name = sqldk_pdb;
	} else if (strncmp(&name[0], "sqltses.pdb", strlen("sqltses.pdb")) == 0) {
		name = sqltses_pdb;
	}

	/* Currently native PDB files are not supported,
	 * so we will have to use the *.txt files created by pdbdump
	 * on windows server and moved to the Linux Server in the
	 * SymbolCache directory 
	*/
	
	sprintf (util_str, name);
	if (strstr(util_str, ".pdb")) {
		txtname = &util_str[0];
		ptr = strrchr(txtname, '.');
		if (ptr) {
			ptr[1]= 't';
			ptr[2]= 'x';
			ptr[3]= 't';
		} else {
			return 0;
		}
	} else {
		/* printf ("PDB file: %s\n", name); */
		return 0;
	}

	mkdir("SymbolCache", 0775);
	if (stat("SymbolCache", &statbuf) < 0) { 
		perror ("Cannot create SymbolCache subdir, PDB cannot be downloaded");
		return 0;
	}

	if ((statbuf.st_mode & S_IFMT) != S_IFDIR) {
		fprintf (stderr, "SymbolCache is not a directory! PDB cannot be downloaded\n");
		return 0;
	}

	if (chdir("SymbolCache") < 0) {
		perror ("chdir to SymbolCache subdir failed.  PDB cannot be downloaded");
		return 0;
	}

	if ((ret=stat(txtname, &statbuf)) ==  0) {
		/* txt already exists */
		build_symbol_table_from_txt(name, txtname);
		goto end;	
	}

	/* while we cannot read the PDB files, we can collect them on the first run so 
   	   we can move to Windows and to pdbdump and push back to the Symbol Cache
	   But let's be selective as there's LOTS of PDB files 
	*/

	if (stat(name, &statbuf) ==  0) {
		/* pdb already exists */
		goto end;	
	}

	if (filter_pdb(name) == 0) {
		goto end;
	}
        sprintf (wget_str, "wget -t 1 -T 120 --user-agent=\"Microsoft-SymbolServer/10.0.10522.521\" \"http://msdl.microsoft.com/download/symbols/%s/%08x%04hx%04hx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%d/%s\" >>wget.log 2>&1",
                        name,
                        p->guid1,
                        p->guid2,
                        p->guid3,
                        p->guid4[0], p->guid4[1],p->guid4[2],p->guid4[3],
                        p->guid5[0], p->guid5[1],p->guid5[2],p->guid5[3],
                        p->guid6,
                        name);


	if (get_pdb_count == 0) {
		fprintf (stderr, "Calling wget to retrieve PDB files from Microsoft Symbol Servers, please wait...\n");
	}

	result = system(wget_str);
	if (result < 0) {
		if (debug) {
			fprintf (stderr, "WGET to get PDB file %s - failed to fork\n", name);
			fprintf (stderr, "   Be sure wget is installed and your PATH variable includes the path to wget\n");
			fprintf (stderr, "   Continuing without getting PDB files\n");
			fprintf (stderr, "%s -- FAILED\n", wget_str );
			wget_fail_cnt++;
		}
	} else if (result > 0) {
		if (get_pdb_count == 0) {
			fprintf (stderr, "WGET failed to get PDB file %s\n", name);
			fprintf (stderr, "   Be sure your proxy server and http_proxy variable is set\n");
			fprintf (stderr, "   It is also possible the PDB file does not exist on the Microsoft Symbol Server\n");
			fprintf (stderr, "   Continuing without getting PDB files\n");
			wget_fail_cnt++;
		}
	} else {
		if (debug) fprintf (stderr, "%s -- SUCCESSFUL\n", wget_str );
		/* build_symbol_table(name); */
	}

	get_pdb_count++;

end:
	if (chdir("..") < 0) {
		perror ("Unexpected error, chdir to to working directory failed.");
		return 0;
	}
}

