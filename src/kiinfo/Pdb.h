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
extern int get_pdb(PdbImage_t *);
extern int print_win_sym(unsigned long, pid_info_t *);
extern int sprint_win_sym(char *, unsigned long, pid_info_t *);
extern char *get_win_sym(unsigned long, pid_info_t *);
extern char *win_symlookup(vtxt_preg_t *, uint64 , uint64 *);
extern vtxt_preg_t *get_win_pregp(uint64, pid_info_t *);
