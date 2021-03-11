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

extern lle_t	*find_add_hash_entry (lle_t ***, int, uint64, int, int);
extern lle_t	*find_remove_hash_entry (lle_t ***, int, uint64, int, int);
extern stklle_t *find_add_stkhash_entry (stklle_t ***, int, int, int, uint64 *, int);
extern lle_t	*find_add_entry (lle_t **, uint64, int, int);
extern lle_t	*find_entry (lle_t **, uint64, int);
extern lle_t	*add_entry_head (lle_t **, uint64, int);
extern void 	*find_add_info (void **, int);
extern void	foreach_hash_entry(void **, int, int (*funct1)(void *, void*), int (*funct2)(const void *, const void *), int32, void *) ;
extern void	foreach_hash_entry_mt(void **, int, int (*funct1)(void *, void*), int (*funct2)(const void *, const void *), int32, void *) ;
extern void	foreach_hash_entry_N(void **, int, int (*funct1)(void *, void*), int (*funct2)(const void *, const void *), int32, void *, int, int) ;
extern void     foreach_hash_entry_l(void **, int, int (*funct1)(void *, void*), int (*funct2)(const void *, const void *), int32, void *) ;
extern int 	hash_count_entries (void *, void *);
extern uint64 	doobsHash(void *, uint32, uint32);
extern void	foreach_server(int (*funct1)(void *, void *), int (*funct2)(const void *, const void *), int32, void *);

extern lle2_t	*find_add_hash_entry2 (lle2_t ***, int, uint64, uint64, int, int);
extern lle2_t	*find_entry2 (lle2_t **, uint64, uint64, int);
extern lle2_t	*find_add_entry2 (lle2_t **, uint64, uint64, int, int);
extern lle2_t	*add_entry_head2 (lle2_t **, uint64, uint64, int);
extern void	foreach_hash_entry2(void **, int, int (*funct1)(void *, void*), int (*funct2)(const void *, const void *), int32, void *) ;
extern lle2_t	*find_remove_hash_entry2 (lle2_t ***, int, uint64, uint64, int, int);

extern void	free_hash_chain(lle_t *);
extern void	free_hash_table(lle_t ***, int);

int 		hash_start_worker_threads();

