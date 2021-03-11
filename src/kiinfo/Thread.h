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
extern int    thread_header_func(void *, void *);
extern int    print_thread_group1_func(void *, void *);
extern int    print_thread_cswitch_func(void *, void *);
extern int    print_thread_readythread_func(void *, void *);
extern int    print_thread_autoboost_func(void *, void *);

extern int    thread_group1_func(void *, void *);
extern int    thread_cswitch_func(void *, void *);
extern int    thread_readythread_func(void *, void *);
extern int    thread_setname_func(void *, void *);
extern int    thread_autoboost_func(void *, void *);
