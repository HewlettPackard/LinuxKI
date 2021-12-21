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

#include <sys/time.h>
#include <sys/errno.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <elf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include "ki_tool.h"
#include "liki.h"
#include "developers.h"
#include "kd_types.h"
#include "globals.h"
#include "info.h"
#include "hash.h"

#define ELF_MAGIC (ELFMAG3 << 24 | ELFMAG2 <<16 | ELFMAG1 <<8 | ELFMAG0)

void
print_phdrs (char *addr) 
{
	Elf64_Ehdr *ehdr = (Elf64_Ehdr *)addr;
	Elf64_Phdr *phdr;
	int i;

	printf ("Ehdr:\n");
	printf ("  e_type:             0x%x\n", ehdr->e_type);
	printf ("  e_machine:          0x%x\n", ehdr->e_machine);
	printf ("  e_version:          0x%x\n", ehdr->e_version);
	printf ("  e_entry:            0x%llx\n", ehdr->e_entry);
	printf ("  e_phoff:            0x%llx\n", ehdr->e_phoff);
	printf ("  e_shoff:            0x%llx\n", ehdr->e_shoff);
	printf ("  e_flags:            x%x\n", ehdr->e_flags);
	printf ("  e_phentsize;        0x%x\n", ehdr->e_phentsize);
	printf ("  e_phnum:            0x%x\n", ehdr->e_phnum);
	printf ("  e_shentsize;        0x%x\n", ehdr->e_shentsize);
	printf ("  e_shnum:            0x%x\n", ehdr->e_shnum);
	printf ("  e_shstrndx:         0x%x\n", ehdr->e_shstrndx);

	for (i = 0; i < ehdr->e_phnum; i++) {
		phdr = (Elf64_Phdr *)(addr + ehdr->e_phoff + (ehdr->e_phentsize*i));
		if ((phdr->p_type == 1) && (phdr->p_flags & 1)) {
		printf ("\nPhdr[%d]:\n", i);
		printf ("  p_type:             0x%x\n", phdr->p_type);
		printf ("  p_flags:            0x%x\n", phdr->p_flags);
		printf ("  p_offset:           0x%llx\n", phdr->p_offset);
		printf ("  p_vaddr:            0x%llx\n", phdr->p_vaddr);
		printf ("  p_paddr:            0x%llx\n", phdr->p_paddr);
		printf ("  p_filesz:           0x%llx\n", phdr->p_filesz);
		printf ("  p_memsz:            0x%llx\n", phdr->p_memsz);
		printf ("  p_align:            0x%llx\n", phdr->p_align);
		}
	}
		

	return;
}


char *
map_elf(char *fname)
{
	int elf_fd;
	char *elfp;
	struct stat statbuf;
	uint64 size;
	int ret;
	char do_printf=1;

	if (objdump_flag) do_printf=0;

	if ((elf_fd = open (fname, O_RDONLY)) < 0) {
		if (!kilive && do_printf) fprintf (stderr, "map_elf: Unable to open %s (errno %d)\n", fname, elf_fd);
		return NULL;
	}

	if ((ret = fstat(elf_fd, &statbuf)) < 0) {
		if (!kilive && do_printf) fprintf (stderr, "map_elf: Unable to fstat %s (errno %d)\n", fname, ret);
		close (elf_fd);
		return NULL;
	}

	size = statbuf.st_size;;
	if (size == 0) {
		if (!kilive && do_printf) fprintf (stderr, "map_elf: File %s is empty\n", fname);
		close (elf_fd);
		return NULL;
	}

	elfp = mmap(NULL, statbuf.st_size, PROT_READ , MAP_SHARED, elf_fd, 0);
	if (elfp == MAP_FAILED) {
		if (!kilive && do_printf) fprintf (stderr, "map_elf: Unable to mmap %s (errno %d)\n", fname, errno);
		close (elf_fd);
		return NULL;
	}

	if (*(unsigned int *)elfp != ELF_MAGIC) {
		/* if (!kilive && do_printf) fprintf (stderr, "map_elf: Invalid ELF MAGIC for %s - 0x%x (expected 0x%x)\n", fname, *(unsigned int *)elfp, ELF_MAGIC); */
		munmap(elfp, size);
		close (elf_fd);
		return NULL;
	}

	if ((elfp[EI_CLASS] != ELFCLASS32) && (elfp[EI_CLASS] != ELFCLASS64)) {
		if (!kilive && do_printf) fprintf (stderr, "map_elf: Invalid CLASS in elf header %d\n", elfp[EI_CLASS]);
		munmap(elfp, size);
		close (elf_fd);
		return NULL;
	}	

	if (elfp[EI_VERSION] == EV_NONE) {
		if (!kilive && do_printf) fprintf(stderr, "map_elf: elf version failed for objfile");
		munmap(elfp, size);
		close (elf_fd);
		return NULL;
	}

	close (elf_fd);
	return elfp;
}

uint64
get_elf_vaddr64(char *addr) 
{
	Elf64_Ehdr *ehdr = (Elf64_Ehdr *)addr;
	Elf64_Phdr *phdr;
	int i;

	for (i = 0; i < ehdr->e_phnum; i++) {
		phdr = (Elf64_Phdr *)(addr + ehdr->e_phoff + (ehdr->e_phentsize*i));
		if ((phdr->p_type == PT_LOAD) && (phdr->p_flags & PF_X)) {
			return (phdr->p_vaddr);
		}
	}

	return 0ull;
}

uint64
get_elf_vaddr32(char *addr) 
{
	Elf32_Ehdr *ehdr = (Elf32_Ehdr *)addr;
	Elf32_Phdr *phdr;
	uint64 vaddr;
	int i;

	for (i = 0; i < ehdr->e_phnum; i++) {
		phdr = (Elf32_Phdr *)((char *)ehdr + ehdr->e_phoff + (ehdr->e_phentsize*i));
		if ((phdr->p_type == PT_LOAD) && (phdr->p_flags & PF_X)) {
			vaddr = phdr->p_vaddr;
			return (vaddr);
		}
	}

	return 0ull;
}


Elf32_Shdr *find_elf32_section(char *elfp, char *sect_name) 
{
	Elf32_Ehdr *ehdr = (Elf32_Ehdr *)elfp;
	Elf32_Shdr *shdr, *shstrndx_shdr;
	char *sh_name, *shstrndx;
	int i;

	shdr = (Elf32_Shdr *)(elfp + ehdr->e_shoff);
	shstrndx_shdr = &shdr[ehdr->e_shstrndx];
	shstrndx = elfp + shstrndx_shdr->sh_offset;
	
	/* Scan the headers looking for the section */
	for (i = 0; i < ehdr->e_shnum; i++) {
		sh_name = &shstrndx[shdr[i].sh_name];
		if (strcmp(sh_name, sect_name) == 0) {
			return &shdr[i];
		}
	}
	return NULL;
}


int bsearch_symtab(Elf64_Addr symptr, elfmap_info_t *elfmapp, int nsyms)
{
	int high, low, mid;
	uint32 found_idx;
	Elf64_Addr tmpptr;

	if (symptr > elfmapp->symtab[nsyms-1].st_value) return -1;

	low = 0;
	high = nsyms - 1;
	while (1) {
		if ((high - low) <= 1) {
			return low;
		}
		mid = (low + high) / 2;
		tmpptr = elfmapp->symtab[mid].st_value;

		if (symptr < tmpptr) {
			high = mid;
		} else {
			low = mid;
		}
	}

	return low;
}	

Elf64_Shdr *find_elf64_section(char *elfp, char *sect_name) 
{
	Elf64_Ehdr *ehdr = (Elf64_Ehdr *)elfp;
	Elf64_Shdr *shdr, *shstrndx_shdr;
	char *sh_name, *shstrndx;
	int i;

	shdr = (Elf64_Shdr *)(elfp + ehdr->e_shoff);
	shstrndx_shdr = &shdr[ehdr->e_shstrndx];
	shstrndx = elfp + shstrndx_shdr->sh_offset;
	
	/* Scan the headers looking for the section */
	for (i = 0; i < ehdr->e_shnum; i++) {
		sh_name = &shstrndx[shdr[i].sh_name];
		if (strcmp(sh_name, sect_name) == 0) {
			return &shdr[i];
		}
	}
	return NULL;
}

int symidx_sort_func(const void *v1, const void *v2) 
{
	const symidx_t *a1 = (symidx_t *)v1;
	const symidx_t *a2 = (symidx_t *)v2;
	int64 diff;

	diff = a2->st_value - a1->st_value;

	if (diff < 0) {
		return 1;
	} else if (diff > 0) {
		return -1;
	} else {
		return 0;
	}
}

char *strtab_lookup32(char *elfp, uint64 idx)
{
	Elf32_Ehdr *ehdr;
	Elf32_Shdr *shdr, *shstrndx_shdr, *symtab_shdr, *strtab_shdr;
	char *strtab;
	Elf32_Sym *symtab;

	symtab_shdr = find_elf32_section(elfp, ".symtab");
	if (symtab_shdr == NULL) return NULL;
	symtab = (Elf32_Sym *)(elfp + symtab_shdr->sh_offset);

	strtab_shdr = find_elf32_section(elfp, ".strtab");
	if (strtab_shdr == NULL) return NULL;
	strtab = elfp + strtab_shdr->sh_offset;

	return &strtab[symtab[idx].st_name];
}

void
build_symtab32(char *elfp, elfmap_info_t *elfmapp)
{
	Elf32_Ehdr *ehdr;
	Elf32_Shdr *shdr, *shstrndx_shdr, *symtab_shdr, *strtab_shdr;
	char *strtab;
	Elf32_Sym *symtab;
	int i, j, found_idx, symtab_nentries, nsyms=0;

	symtab_shdr = find_elf32_section(elfp, ".symtab");
	if (symtab_shdr == NULL) return;
	symtab = (Elf32_Sym *)(elfp + symtab_shdr->sh_offset);
	symtab_nentries = symtab_shdr->sh_size / symtab_shdr->sh_entsize;

	strtab_shdr = find_elf32_section(elfp, ".strtab");
	if (strtab_shdr == NULL) return;
	strtab = elfp + strtab_shdr->sh_offset;

	for (i = 0; i < symtab_nentries; i++) {
		if ((ELF32_ST_TYPE(symtab[i].st_info) == STT_FUNC) && symtab[i].st_value) {
				nsyms++;
		}
	}

	if (elfmapp->symtab = malloc(nsyms*sizeof(symidx_t))) {
		MALLOC_LOG(elfmapp->symtab, nsyms*sizeof(symidx_t));
		for (i = 0, j=0; i < symtab_nentries; i++) {
			if ((ELF32_ST_TYPE(symtab[i].st_info) == STT_FUNC) && symtab[i].st_value) {
				elfmapp->symtab[j].st_value =  symtab[i].st_value;
				elfmapp->symtab[j].idx = i;
				j++;
				if (j >= nsyms) break;
			}
		}
		qsort(&elfmapp->symtab[0], nsyms, sizeof(symidx_t), symidx_sort_func);
		elfmapp->nsym = nsyms;
	}
}

char *strtab_lookup64(char *elfp, uint64 idx)
{
	Elf64_Ehdr *ehdr;
	Elf64_Shdr *symtab_shdr, *strtab_shdr;
	char *strtab;
	Elf64_Sym *symtab;

	symtab_shdr = find_elf64_section(elfp, ".symtab");
	if (symtab_shdr == NULL) return NULL;
	symtab = (Elf64_Sym *)(elfp + symtab_shdr->sh_offset);

	strtab_shdr = find_elf64_section(elfp, ".strtab");
	if (strtab_shdr == NULL) return NULL;
	strtab = elfp + strtab_shdr->sh_offset;

	return &strtab[symtab[idx].st_name];
}

void
build_symtab64(char *elfp, elfmap_info_t *elfmapp)
{
	Elf64_Ehdr *ehdr;
	Elf64_Shdr *symtab_shdr, *strtab_shdr;
	char *strtab;
	Elf64_Sym *symtab;
	int i, j, found_idx, symtab_nentries, nsyms=0;

	symtab_shdr = find_elf64_section(elfp, ".symtab");
	if (symtab_shdr == NULL) return;
	symtab = (Elf64_Sym *)(elfp + symtab_shdr->sh_offset);
	symtab_nentries = symtab_shdr->sh_size / symtab_shdr->sh_entsize;

	strtab_shdr = find_elf64_section(elfp, ".strtab");
	if (strtab_shdr == NULL) return;
	strtab = elfp + strtab_shdr->sh_offset;

	for (i = 0; i < symtab_nentries; i++) {
		if ((ELF64_ST_TYPE(symtab[i].st_info) == STT_FUNC) && symtab[i].st_value) {
				nsyms++;
		}
	}

	if (elfmapp->symtab = malloc(nsyms*sizeof(symidx_t))) {
		MALLOC_LOG(elfmapp->symtab, nsyms*sizeof(symidx_t));
		for (i = 0, j=0; i < symtab_nentries; i++) {
			if ((ELF64_ST_TYPE(symtab[i].st_info) == STT_FUNC) && symtab[i].st_value) {
				elfmapp->symtab[j].st_value =  symtab[i].st_value;
				elfmapp->symtab[j].idx = i;
				j++;
				if (j >= nsyms) break;
			}
		}
		qsort(&elfmapp->symtab[0], nsyms, sizeof(symidx_t), symidx_sort_func);
		elfmapp->nsym = nsyms;
	}
}

char *symlookup(void *arg1, Elf64_Addr symaddr, uint64 *offsetp) 
{
	vtxt_preg_t *pregp = (vtxt_preg_t *)arg1;
	char *elfp;
	uint64 offset;
	uint64 tmpptr;
	elfmap_info_t *elfmapp;
	int symtab_idx;
	uint32 found_idx;

	if (pregp == NULL) return NULL;
	if ((elfmapp = pregp->elfmapp) == NULL) return NULL;
	if ((elfp = pregp->elfp) == NULL) return NULL;

	/* printf ("\nsymlookup():  addr: 0x%llx   pregp: vaddr 0x%llx p_off 0x%llx elf_vaddr 0x%llx\n", symaddr, pregp->p_vaddr, pregp->p_off, pregp->elf_vaddr); */

	/* this is a bit tricky.  We have the virtual address for the ELF object in memory (from /proc/<PID>/maps), and
	 * we have the default virtual address defined in the object file.  These MAY not be the same.   So we will get
	 * the offset from the start of the ELF in memory and use that to map the symaddr into the ELF file.    
	 */
	symaddr = symaddr - (pregp->p_vaddr - pregp->elf_vaddr);

	/* printf ("symlookup():  addr: 0x%llx   pregp: vaddr 0x%llx p_off 0x%llx elf_vaddr 0x%llx\n", symaddr, pregp->p_vaddr, pregp->p_off, pregp->elf_vaddr); */
	/* build the sorted symbol table, if it is not already built */
	if (elfmapp->symtab == NULL)  {
		elfp[EI_CLASS] == ELFCLASS32 ? build_symtab32(elfp, elfmapp) : build_symtab64(elfp, elfmapp);
	}

	if (elfmapp->nsym == 0) return 0;
	/* perform bineary search of sorted symbol table file */
	symtab_idx = bsearch_symtab(symaddr, elfmapp, elfmapp->nsym);	

	if (symtab_idx > 0) {
		tmpptr = elfmapp->symtab[symtab_idx].st_value;
		found_idx = elfmapp->symtab[symtab_idx].idx;
		*offsetp = symaddr-tmpptr;
		/* printf ("addr: 0x%llx Found Symbol at index [%d]!  start: 0x%llx  %s+0x%x\n", symaddr, found_idx, tmpptr, &strtab[symtab[found_idx].st_name], *offsetp);  */
		return ( elfp[EI_CLASS] == ELFCLASS32 ? strtab_lookup32(elfp, found_idx) : strtab_lookup64(elfp, found_idx) );
	} else {
		*offsetp = 0;
		/* printf ("Symbol Not Found!\n"); */
		return NULL;
	}
}

int load_elf(char *fnamep, vtxt_preg_t *pregp)
{
	char *elfp;
	elfmap_info_t *elfmapp;

	/* called only if objfile= is passed to kiinfo */
	if (fnamep == NULL) return 0;
	
	if (debug) printf ("Loading symbols from %s\n", fnamep);

	/* check to see if elf already mapped.   If so, just return the saved mmap addr */
	elfmapp = GET_ELFMAPP(&globals->elfmap_hash, ELFMAP_KEY(fnamep));
	if (elfmapp->elfp) {
		elfp = elfmapp->elfp;
	} else {
		if ((elfp = map_elf(fnamep)) == NULL) {	
			if (debug) fprintf (stderr, "Failed to map in symbols from %s\n", fnamep);
			return 0;
		}

		elfmapp->elfp = elfp;
	}
	
	if (pregp->filename == NULL) {	
		pregp->filename = fnamep;
	}

	pregp->p_type = elfp[EI_CLASS];
	pregp->elfp = elfp;
	pregp->elfmapp = elfmapp;

	switch (pregp->p_type) {
		case ELFCLASS64:
		    {
			Elf64_Shdr *symtab_shdr, *strtab_shdr;

			if (symtab_shdr = find_elf64_section(elfp, ".symtab")) {
				pregp->symbols = (Elf64_Sym *)(elfp + symtab_shdr->sh_offset);
				pregp->nsyms = symtab_shdr->sh_size / symtab_shdr->sh_entsize;

				if (strtab_shdr = find_elf64_section(elfp, ".strtab")) {
					pregp->strings = elfp + strtab_shdr->sh_offset; 
				}
		    		pregp->elf_vaddr = get_elf_vaddr64(elfp); 

			} else {
				if (debug) fprintf (stderr, " - Symbol Table not found!");
				pregp->elfp = NULL;
			}
		    }
		    break;	
		case ELFCLASS32:
		    {
			Elf32_Shdr *symtab_shdr, *strtab_shdr;

			if (symtab_shdr = find_elf32_section(elfp, ".symtab")) {
				pregp->symbols = (Elf32_Sym *)(elfp + symtab_shdr->sh_offset); 
				pregp->nsyms = symtab_shdr->sh_size / symtab_shdr->sh_entsize;

				if (strtab_shdr = find_elf32_section(elfp, ".strtab")) {
					pregp->strings = elfp + strtab_shdr->sh_offset; 
				}
		    		pregp->elf_vaddr = get_elf_vaddr32(elfp); 
			} else {
				if (debug) fprintf (stderr, " - Symbol Table not found!");
				pregp->elfp = NULL;
			}
		    }
		    break;
		default:
			break;
	}
	if (debug) printf ("\n");

	/* for symlookup, the p_vaddr should be filled in.  But for the obfjile, it is not so let's fill it in */
	if (pregp->p_vaddr == 0ull) pregp->p_vaddr = pregp->elf_vaddr;
	
	return 0;
}

void *find_vtext_preg(void *arg1, uint64 pc)
{
	vtxt_preg_t *pregp = (vtxt_preg_t *)arg1;

	while (pregp != NULL) {
		if ((pc >= pregp->p_vaddr) && (pc < pregp->p_endaddr)) {
			/* printf ("pc 0x%llx, pregp 0x%llx, p_vaddr 0x%llx p_endaddr 0x%llx\n", pc, pregp, pregp->p_vaddr, pregp->p_endaddr); */
			return pregp;
		}

		pregp = (vtxt_preg_t *)pregp->lle.next;
	}
	
	return NULL;
}

void dump_elf32(char *elfp, char *fname) {
	Elf32_Ehdr *ehdr;
	Elf32_Shdr *shdr, *shstrndx_shdr, *symtab_shdr, *strtab_shdr;
	Elf32_Sym *symtab;
	char *hitp;
	char *sptr;
	int symfd, ret;

	if (elfp == NULL) return;

	sptr = fname;
	while (hitp = strchr(sptr, '/')) {
		hitp[0] = '?';
		sptr = hitp + 1;
	}	

	if ((symfd = open(fname, O_WRONLY | O_CREAT, 00777)) < 0) {
		perror ("open() failed");
		fprintf (stderr, "Unable to open %s (errno %d)\n", fname, errno);
		return;
	}

	ehdr = (Elf32_Ehdr *)elfp;
	if (write (symfd, ehdr, ehdr->e_ehsize) == -1) return;

	lseek (symfd, ehdr->e_phoff, 0);
	if (write (symfd, (char *)elfp + ehdr->e_phoff, ehdr->e_phnum * ehdr->e_phentsize) == -1) return;

	lseek (symfd, ehdr->e_shoff, 0);
	if (write (symfd, (char *)elfp + ehdr->e_shoff, ehdr->e_shnum * ehdr->e_shentsize) == -1) return;

	shdr = (Elf32_Shdr *)(elfp + ehdr->e_shoff);
	shstrndx_shdr = &shdr[ehdr->e_shstrndx];
	lseek (symfd, shstrndx_shdr->sh_offset, 0);
	if (write (symfd, (char *)elfp + shstrndx_shdr->sh_offset, shstrndx_shdr->sh_size) == -1) return;

	symtab_shdr = find_elf32_section(elfp, ".symtab");
	if (symtab_shdr == NULL)  goto errout;

	lseek (symfd, symtab_shdr->sh_offset, 0);
	if (write (symfd, (char *)elfp + symtab_shdr->sh_offset, symtab_shdr->sh_size) == -1) return;

	strtab_shdr = find_elf32_section(elfp, ".strtab");
	lseek (symfd, strtab_shdr->sh_offset, 0);
	if (write (symfd, (char *)elfp + strtab_shdr->sh_offset, strtab_shdr->sh_size) == -1) return;

	close(symfd);
	return;

errout:
	close(symfd);
	unlink(fname);
}

void dump_elf64(char *elfp, char *fname) {
	Elf64_Ehdr *ehdr;
	Elf64_Shdr *shdr, *shstrndx_shdr, *symtab_shdr, *strtab_shdr;
	Elf64_Sym *symtab;
	char *hitp;
	char *sptr;
	int symfd;

	if (elfp == NULL) return;

	sptr = fname;
	while (hitp = strchr(sptr, '/')) {
		hitp[0] = '?';
		sptr = hitp + 1;
	}	

	if ((symfd = open(fname, O_WRONLY | O_CREAT, 00777)) < 0) {
		perror ("open() failed");
		fprintf (stderr, "Unable to open %s (errno %d)\n", fname, errno);
		return;
	}

	ehdr = (Elf64_Ehdr *)elfp;
	if (write (symfd, ehdr, ehdr->e_ehsize) == -1) return;

	lseek (symfd, ehdr->e_phoff, 0);
	if (write (symfd, (char *)elfp + ehdr->e_phoff, ehdr->e_phnum * ehdr->e_phentsize) == -1) return;

	lseek (symfd, ehdr->e_shoff, 0);
	if (write (symfd, (char *)elfp + ehdr->e_shoff, ehdr->e_shnum * ehdr->e_shentsize) == -1) return;

	shdr = (Elf64_Shdr *)(elfp + ehdr->e_shoff);
	shstrndx_shdr = &shdr[ehdr->e_shstrndx];
	lseek (symfd, shstrndx_shdr->sh_offset, 0);
	if (write (symfd, (char *)elfp + shstrndx_shdr->sh_offset, shstrndx_shdr->sh_size) == -1) return;

	symtab_shdr = find_elf64_section(elfp, ".symtab");
	if (symtab_shdr == NULL)  goto errout;

	lseek (symfd, symtab_shdr->sh_offset, 0);
	if (write (symfd, (char *)elfp + symtab_shdr->sh_offset, symtab_shdr->sh_size) == -1) return;

	strtab_shdr = find_elf64_section(elfp, ".strtab");
	if (lseek (symfd, strtab_shdr->sh_offset, 0) == -1) return;
	if (write (symfd, (char *)elfp + strtab_shdr->sh_offset, strtab_shdr->sh_size) == -1) return;

	close(symfd);
	return;

errout:
	close(symfd);
	unlink(fname);
}

void
objdump()	
{
	int 	ret;
	FILE *f = NULL;
	char fname[30];
	char dname[30];
	char *rtnptr;
	char filename[512];
	char *elfp = NULL;

	if (debug) printf ("objdump()\n");

	if (is_alive) return;

	sprintf (fname, "objfiles.%s", timestamp);
        if ((f = fopen(fname, "r")) == NULL) {
                if (debug) printf ("Unable to open file %s, errno %d\n", fname, errno);
                return;
        }

	sprintf(dname, "objdump.%s", timestamp);
        ret = mkdir(dname, 0777);
        if (ret && (errno != EEXIST)) {
                fprintf (stderr, "Unable to make objdump directory, errno %d\n", errno);
                fprintf (stderr, "Exiting\n");
		return;
        }

	cwd = get_current_dir_name();
	if (chdir(dname) == -1) {
                fprintf (stderr, "Unable to change to directory %s, errno %d\n", dname, errno);
                fprintf (stderr, "Exiting\n");
		return;
	}	

        while (rtnptr = fgets((char*)&input_str, 511, f)) {
		sscanf(input_str, "%s", filename);
		if (debug) printf ("map_elf: %s\n", filename);

		elfp = map_elf(filename);	
		if (elfp) {
			elfp[EI_CLASS] == ELFCLASS32 ? dump_elf32(elfp, filename) : dump_elf64(elfp, filename);
		}
	}
	
	if (cwd) {
		if (chdir(cwd) == -1) {
	                fprintf (stderr, "Unable to change to directory %s, errno %d\n", cwd, errno);
                	fprintf (stderr, "Exiting\n");
			return;
		}
	}	
}

/*  while technically not related to ELF, the .map file lookups borrow heavily from
 *  the symlookup function, so we will keep it in the elf.c file
 */
int
bsearch_maptab(uint64 symptr, map_entry_t *maptab, int nsym)
{
	int high, low, mid;
	uint32 found_idx;
	uint64 tmpptr;

	/* do a quick check of 1st and last entries */
	if ((symptr < maptab[0].addr) || (symptr > maptab[nsym-1].addr)) 
		return -1;

	low = 0;
	high = nsym - 1;
	while (1) {
		if ((high - low) <= 1) {
			return low;
		}
		mid = (low + high) / 2;
		tmpptr = maptab[mid].addr;

		if (symptr < tmpptr) {
			high = mid;
		} else {
			low = mid;
		}
	}

	return low;
}	

char *
maplookup(void *arg1, uint64 addr, uint64 *offsetp) 
{
	vtxt_preg_t *mapinfop = (vtxt_preg_t *)arg1;
	map_entry_t *maptab;
	int nsyms;
	char *nameptr, *pos, *prev;
	int maptab_idx;

	/* printf ("maplookup() 0x%llx\n", addr); */
	if (mapinfop == NULL) return NULL;
	maptab = mapinfop->symbols;
	nsyms = mapinfop->nsyms;

	*offsetp = 0;
	if ((nsyms <= 0) || (maptab == NULL) || (mapinfop->elfp == NULL)) return NULL;

	/* perform binary search of sorted symbol table file */
	maptab_idx = bsearch_maptab(addr, maptab, nsyms);	

	if (maptab_idx > 0) {

		/* if the offset is large, then the addr is likely invalid, so skip */
		*offsetp = addr - maptab[maptab_idx].addr;
		if ((*offsetp) > 0x100000) return NULL;

		nameptr = mapinfop->elfp + maptab[maptab_idx].nameptr;

		/* The symbol names in the .map file are not null terminated.  So we will 
		 * make use of the util_str to provide a null terminate symbol name limited to 
		 * 80 bytes
		 */
		strncpy (util_str, nameptr, 81);
		if (pos = strchr(util_str, 10)) {
			prev = pos - 1;
			if (prev[0] == 32)
				prev[0] = 0;
			else
				pos[0] = 0;
		}

		return util_str;
	} else {
		/* printf ("Symbol Not Found!\n"); */
		return NULL;
	}
}
