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

/* option_iface.h
 * Authors:   Georges Aureau, Peter Hryczanek
 */

#ifndef _OPTION_IFACE_INCLUDED
#define _OPTION_IFACE_INCLUDED


/*
** Flags
*/

/*
** Warning. I kludged this. I added f_arch and changed f_type to a short.
** kmmeinfo f_type is an int, and it doesn't have an f_arch. But for 
** the vmtrace in kmeminfo to work (it is declared extern in crashinfo.c)
** f_type in kmeminfo had to be the same as f_arch + f_type in crashinfo...
*/

typedef struct flag {
	char *f_name;
	char *f_value;
	short f_arch;           /* 0 = both, 1 = PA only, 2 = IA64 only */
	short f_type;           /* Value mandatory/optional */
	char *f_decode;         /* "i" integer, "s" string,
				   "v" space.offset virtual address */
} flag_t;

/*
** Options
*/

struct init;
struct arg;

typedef struct option {
	char *    o_name;               /* option name */
	char *    o_short;              /* option short cut */
	char *    o_arg;
	flag_t  * o_flags;
	int       o_type;
	int       o_done;
	char *    o_decode;
	void     (*o_entry)(struct init *, struct arg *);
} option_t;

/* Option type (o_type) */
#define OT_REG          0x0000
#define OT_ONCE         0x0001  /* option should be processed once */
#define OT_CONF         0x0002  /* A configruration option */
#define OT_OPTARG       0x0004  /* Argument is optional (when o_arg set) */
#define OT_MANARG       0x0008  /* Argument is mandatory */
#define OT_HIDDEN       0x1000  /* hidden option, ie don't show in usage */
#define OT_OARG         (OT_REG|OT_OPTARG)

/* Flag type (f_type) */
#define FT_REG    0x0001
#define FT_OPT    0x0002
#define FT_HIDDEN 0x0004

/* Arch type (f_arch) */
#define FA_ALL  0
#define FA_PA   1
#define FA_IA64 2

/*
** Output
*/

typedef struct {
	uint64 space;
	uint64 offset;
} vaddr_t;

typedef union {
	uint64  i;      /* integer */
	char *  s;      /* string */
	vaddr_t v;      /* virtual address */
} value_t;

typedef struct prop {
	struct prop *p_nextp;
	char *       p_name;
	int          p_valid;
	value_t      p_value;
} prop_t;

typedef struct arg {
	prop_t *a_props;
	value_t a_value;
	int     a_valid;        /* arg is valid - Pete */
} arg_t;

/*
** Action list
*/


typedef struct action {
	struct action *a_next;          /* Need to be first */
	void          (*a_entry)(struct init *, struct arg *);
	arg_t         *a_arg;
} action_t;


/*
** Main init structure
*/

typedef struct init {
	int       i_argc;
	char    **i_argv;
	char     *i_trace;
	option_t *i_options;
	action_t *i_actions;
	int       i_exit;
	char     *i_data;
} init_t;


/*
** Funtion Prototypes 
*/

extern prop_t * prop_lookup(prop_t *, char *);
extern void  option_usage(init_t *, char *, char *);
extern void  action_invoke(init_t *);
extern void  option_decode(init_t *);
extern void  hidden(void);

#endif
