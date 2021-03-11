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
#include <stdarg.h>
#include <string.h>
#include <strings.h>
#include <sys/errno.h>
#include <sys/types.h>

extern char HTML;

int
BOLD(const char *format, ...)
{
        va_list ap;

        va_start(ap, format);
	if (HTML)  {
		printf ("<b>");
        	vprintf(format, ap);
		printf ("</b>");
	} else {	
                vprintf(format, ap);
        }

        return 0;
}

char *
SPF(char *str, const char *format, ...)
{
        va_list ap;
        va_start(ap, format);
        vsprintf(str, format, ap);
        return str;
}
