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

/* option.c
 * Authors:   Georges Aureau, Peter Hryczanek
 */

#include <libgen.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include "ki_tool.h"
#include "developers.h"
#include "liki.h"
#include "globals.h"
#include "option_iface.h"
#include "option_private.h"

static void
flag_usage(flag_t *flag, int format)
{
	if (flag->f_type & FT_HIDDEN) {
		return;
	}

	fprintf(stderr, format ? "\t\t\t%s" : " %s", flag->f_name);
	if (flag->f_value) {
		fprintf(stderr, (flag->f_type & FT_OPT)?"[=<%s>]":"=<%s>",
			flag->f_value);
	}
	if (flag->f_arch == FA_PA)
		fprintf(stderr, "\t(PA Only)");
	else if (flag->f_arch == FA_IA64)
		fprintf(stderr, "\t(IA64 Only)");

	fprintf(stderr, "\n");
}

void
option_usage(init_t *init, char *msg, char *option)
{
	option_t *opt;
	flag_t  *ofl;
	char *progname;

	if (msg) {
		fprintf(stderr, "Error: %s\n", msg);
	}

	fprintf(stderr, 
"Usage:   %s [options ...]\n"
"Options:\n",
		BASENAME(init->i_argv[0])
	);

	for (opt=init->i_options; opt->o_name; opt++) {
		if (option && (strcmp(opt->o_name, option))) {
			continue;
		}

		/* Do not print hidden options */
		if (opt->o_type & OT_HIDDEN) {
			continue;
		}

		if (opt->o_short) {
			fprintf(stderr, "\t-%s | ", opt->o_short);
		} else
			fprintf(stderr, "\t     ");

		if (opt->o_arg) {
			fprintf(stderr, "-%s %s", opt->o_name, opt->o_arg);
		} else {
			fprintf(stderr, "-%s", opt->o_name);
		}

		if (ofl = opt->o_flags) {
			int format = 0;
			if (opt->o_arg) 
				fprintf(stderr,"[,flag,flag...]\n");
			else
				fprintf(stderr," [flag,flag...]\n");
			fprintf(stderr, "\t\t flags:");
			while(ofl->f_name) {
				flag_usage(ofl, format);
				format = 1;
				ofl++;
			}
		} else {
			putc('\n', stderr);
		}
	}

	_exit(10);
}

static
flag_t *
flag_lookup(flag_t *flags, char *string)
{
	flag_t *flag;

	for(flag=flags; flag->f_name; flag++) {
		if (strcmp(string, flag->f_name) == 0)
			return flag;
	}
	return (flag_t *)0;
}

static
prop_t *
flag_decode(flag_t *flags, char *string)
{
	char *name;
	char *value;
	flag_t *flag;
	prop_t *prop;

	name = string;
	value = strchr(string, '=');
	if (value) *value++ = 0;

	flag = flag_lookup(flags, name);
	if (!flag) {
		return (prop_t *)0;
	}
	
	prop = (prop_t *)calloc(1,sizeof(prop_t));
	prop->p_name = flag->f_name;

	if (value) {
		if (!value_decode(*(flag->f_decode),&(prop->p_value),value)) {
			return (prop_t *)0;
		}
		prop->p_valid = 1;
	} else {
		/*
		** Value not specified: return failure if mandatory
		*/
		if (flag->f_type & FT_REG) {	/* Mandatory */
			return (prop_t *)0;
		}

		prop->p_valid = 0;
	}
	return prop;
}

prop_t *
prop_lookup(prop_t *prop, char *name)
{
	while (prop) {
		if (strcmp(name, prop->p_name) == 0)
			return prop;
		prop = prop->p_nextp;
	}
	return (prop_t *)0;
}

/*
** Returns a linked list of properties
*/
static
prop_t *
flags_decode(option_t *opt, char *string)
{
	char *flag;
	char *next;
	prop_t *prop, *head, *last;

	flag = string;
	head = (prop_t *)0;
	last = (prop_t *)0;

	do {
		next = strchr(flag, ',');
		if (next) *next++ = 0;

		/*
		** At this point we have flag pointing to "max=10"
		*/
		prop = flag_decode(opt->o_flags, flag);

		if (!prop) {
			return (prop_t *)0;
		}

		if (head == (prop_t *)0) {
			head = prop;
		}

		if (last) {
			last->p_nextp = prop;
		}
		last = prop;

		flag = next;
	} while(flag);

	return head;
}

static
int
value_decode(char type, value_t *value, char *string)
{
	char *dot;

	switch(type) {
	case 'i':
		if (strstr(string, "0x")) {
			sscanf(string,"0x%llx", &value->i);
		} else {
			value->i = atol(string);
		}
		break;
	case 's':
		value->s = string;
		break;
	case 'v':
		dot = strchr(string, '.');
		if (dot) {
			*dot++ = 0;
			value->v.space = atol(string);
			value->v.offset = atol(dot);
		} else {
			value->v.space = 0ll;
			value->v.offset = atol(string);
		}
		break;
	default:
		return 0;
	}
	return 1;	/* return success */
}

static int
check_vmunix(char *string)
{
	int fd;
	uint32 magic = 0;

	fd = open(string, O_RDONLY);

	if (fd == -1) {
		return 0;
	}

	read(fd, &magic, 4);
	close(fd);

	/* ELF or SOM (PA-RISC1.1) executables */
	if (magic == 0x7f454c46 || magic == 0x02100107) {
		return 1;
        }

	return 0;
}


/*
** Determines whether string is a coredir or a vmunix file.
** Attempts to take care of an optional arg being the same as a directory or
** file - i.e. if a file or dir exists then try and deterimine wether it is
** really a dump or not (well for a regular file anway - if it's a dir then
** we assume it really is a dumpdir...)
*/
static int
check_core(char *string)
{
	struct stat buf;

	if (stat(string, &buf) != 0)
		return 0; /* Doesn't exist */

	/* Directory or special file */
	if (S_ISREG(buf.st_mode) == 0) {
		return 1;
        }

	/* Regular file, check if big enough for a vmunix */
	if (buf.st_size < 8192000) {
		return 0;
	}

	return check_vmunix(string);
}



/*
** string is a pointer to a list 
**   0x1234,pid=1,max=10
*/

/* Pete. 
** I think this function should cope with either a true argument or flags
** with no argument.
** eg myprogram -option [arg][,flag,flag]
**    myprogram -option [flag,flag]
*/

static
arg_t *
arg_decode(option_t *opt, char *string)
{
	arg_t *arg;
	char *flags;
	char *comma = 0;
	char *dot;
	struct stat buf;

	arg = (arg_t *)calloc(1, sizeof(arg_t));
	arg->a_valid = 0;

	if (opt->o_flags) {
		if (opt->o_arg)  {
			comma = strchr(string, ',');
			if (comma)  {
				*comma++ = 0;
				flags = comma;
			} else  {
				if (opt->o_type & OT_MANARG) {
					flags = 0;
				} else
					flags = string;
			}
		} else
			flags = string;
	} else {
		flags = 0; 
	}

	/*
	** Decode argument value
	*/
	if (opt->o_decode == NULL) {
		arg->a_valid = 0;
	} else {
		arg->a_valid = value_decode(*(opt->o_decode), &(arg->a_value), string);
	}

	if (!arg->a_valid && (opt->o_type & OT_MANARG))
		return (arg_t *)0; /* mandatory arg missing */

	/*
	** We could have an optional argument...
	** ie. if it's not there, we could either reach the
	** next option "-foo" or core file...
	*/

	if (!(opt->o_type & OT_MANARG)) {
		/*
		** if *string == '-', we are at the next option 
		*/
		if (*string == '-')
			return (arg_t *)0;
		/*
		** The complicated case. We may have a coredir or 
		** vmunix/corefile pair.  This is for HP-UX only.
		if (check_core(string))
			return (arg_t *)0;
		*/
	}
	
	/*
	** If not the next option and not a core file then
	** assume this should be a flag
	*/
	if (flags) { /* We should find at least one valid flag */
		arg->a_props = flags_decode(opt, flags);
		if (!arg->a_props && !arg->a_valid)
			return (arg_t *)-1; /* dodgy flag ? */
	}

	return arg;
}

void
action_invoke(init_t *init)
{
	action_t *act;

	for (act=init->i_actions; act; act=act->a_next) {
		if (act->a_entry) {
                        (*act->a_entry)(init, act->a_arg);
                }
        }
}

static
action_t *
action_add(action_t *act, void (*func)(struct init *, arg_t *), arg_t *arg)
{
	action_t *new;

	new = (action_t *)malloc(sizeof(action_t));
	new->a_entry = func;
	new->a_arg = arg;
	new->a_next = NULL;
	act->a_next = new;
	return new;
}


static
option_t *
option_lookup(char *name, option_t *options)
{
	option_t *opt;

	for (opt=options; opt->o_name; opt++) {
		if (strcmp(opt->o_name, name) == 0) {
			return opt;
		}
		if (opt->o_short && strcmp(opt->o_short, name) == 0) {
			return opt;
		}
	}
	return NULL;
}

void
option_decode(init_t *init)
{
	int i;
	/* caddr_t arg; */
	arg_t *arg;
	char **argv;
	int argc;
	option_t *options;
	option_t *opt;
	action_t *act;
	char * msg;
	int noptions = 0;

	argc = init->i_argc;
	argv = init->i_argv;
	options = init->i_options;

	act = (action_t *) &init->i_actions;

	for (i=1; i<argc; i++) {

		if (*argv[i] == '-') {
			opt = option_lookup(argv[i]+1, options);
			if (opt == NULL) {
				option_usage(init, "Invalid option", NULL);
			} else {
				noptions++;
			}

			/*
			** If the option can have an argument and/or flags
			** then do argument processing.
			*/
			if (opt->o_arg || opt->o_flags) {
				if (i==(argc-1)) {
					if (!(opt->o_type & OT_MANARG)) {
						arg = NULL;
					} else {
						option_usage(init, "Argument missing", NULL);
					}
				} else {
					i++;
					arg = arg_decode(opt, argv[i]);
					if (arg == NULL) {
						if (!(opt->o_type & OT_MANARG)){
							i--;
						} else {
							option_usage(init, "Invalid argument", NULL);
						}
					}
					if (arg == (arg_t *)-1)  {
						/*
						** If you don't understand this
						** piece of code, call Pete :-)
						*/
						option_usage(init, "Invalid flag or trace file", NULL);
					}
				}
			} else {
				arg = NULL;
			}

			/*
			** Configuration options are processed immediatly, ie.
			** without building an action for a delayed processing.
			*/
			if (opt->o_type & OT_CONF) {
				(*opt->o_entry)(init, arg);
				continue;
			}

			if (opt->o_type & OT_ONCE) {
				if (!opt->o_done) {
					opt->o_done = 1;
					act = action_add(act, opt->o_entry, arg);
				}
			} else {
				act = action_add(act, opt->o_entry, arg);
			}
		} else {
			option_usage(init, "Unexpected argument", NULL);

/*
For HP-UX if there is a vmunix file:

			if (i == (argc-1)) {
				init->i_trace = argv[i];
			} else {
				option_usage(init, msg, NULL);
			}
*/

			break;
		}
	}

	if (noptions == 0) {
		option_usage(init, "kiinfo option expected", NULL);
	}
}
