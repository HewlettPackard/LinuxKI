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
#include <strings.h>
#include <time.h>
#include <sys/errno.h>
#include <sys/types.h>
#include "ki_tool.h"
#include "liki.h"
#include "winki.h"
#include "developers.h"
#include "kd_types.h"
#include "globals.h"
#include "info.h"
#include "hash.h"
#include "scsi.h"
#include "Provider.h"
#include "Pdb.h"

int
print_pdb_image(PdbImage_t *p)
{
	int i;
	printf (" PdbImage: %s %08x-%04hx-%04hx-", p->Name, p->guid1, p->guid2, p->guid3);

	for (i = 0; i < 4; i++) {
		printf ("%02hhx", p->guid4[i]);
	}
	printf ("-");
	for (i = 0; i < 4; i++) {
		printf ("%02hhx", p->guid5[i]);
	}
	printf ("-%d", p->guid6);
}
	
int
pdb_image_func(PdbImage_t *p)
{

	get_pdb(p);
}

int
print_control_image(ControlImage_t *p)
{
	uint16 *chr;

	chr = &p->Name[0];
	printf (" ControlImage: size=%d datetime=0x%x", p->ImageSize, p->TimeDateStamp);
	printf (" Orig=\"");
	PRINT_WIN_NAME2(chr);
	printf ("\" FileDesc=\"");
	PRINT_WIN_NAME2(chr);
	printf ("\" FileVer=\"");
	PRINT_WIN_NAME2(chr);
	printf ("\" BinVer=\"");
	PRINT_WIN_NAME2(chr);
	printf ("\" VerLang=\"");
	PRINT_WIN_NAME2(chr);
	printf ("\" Product=\"");
	PRINT_WIN_NAME2(chr);
	printf ("\" Company=\"");
	PRINT_WIN_NAME2(chr);
	printf ("\" ProdVer=\"");
	PRINT_WIN_NAME2(chr);
	printf ("\" FileId=\"");
	PRINT_WIN_NAME2(chr);
	printf ("\" ProgramId=\"");
	PRINT_WIN_NAME2(chr);
}

int
control_image_func(ControlImage_t *p)
{
	uint16 *chr;
	char	str[512];
	char	*ptr;
	pdb_info_t *pdbinfop;
	uint32	key;

	chr = &p->Name[0];
	PRINT_WIN_NAME2_STR(str, chr);

	/* convert to PDB name */
	if ((ptr = strrchr(str, '.')) == NULL) return 0;
	ptr[1] = 'p';
	ptr[2] = 'd';
	ptr[3] = 'b';

	key = doobsHash(&str[0], strlen(str), 0xff);
	pdbinfop = (pdb_info_t *)find_add_strhash_entry((strlle_t ***)&globals->pdbmap_hash, PDB_HSIZE, PDB_HASH(key), sizeof(pdb_info_t), &str[0], strlen(str));

	pdbinfop->ControlImagePtr = (void *)p;
	/* printf ("ImageName: %s [%d] Ptr: 0x%llx\n", pdbinfop->strlle.key, strlen(pdbinfop->strlle.key), pdbinfop->ControlImagePtr); */
}
