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

/* option_private.h
 * Authors:   Georges Aureau, Peter Hryczanek
 */

#ifndef _OPTION_PRIVATE_INCLUDED
#define _OPTION_PRIVATE_INCLUDED

#define BASENAME(name)  (strchr(name, '/') ? strrchr(name, '/') + 1 : name)

/* Funtion Prototypes */

static void       flag_usage(flag_t *, int);
static flag_t   * flag_lookup(flag_t *, char *);
static prop_t   * flag_decode(flag_t *, char *);
static prop_t   * flags_decode(option_t *, char *);
static int        value_decode(char, value_t *, char *);
static arg_t    * arg_decode(option_t *, char *);
static action_t * action_add(action_t *, void  (*)(), arg_t *);
static option_t * option_lookup(char *, option_t *);

#endif
