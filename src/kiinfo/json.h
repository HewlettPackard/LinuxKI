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

/*   MACRO definitions  */


#define CHILDREN        0x0001
#define JSON_OBJECT     0x0002
#define JSON_ARRAY      0x0004

#define JSPARENT		0
#define JSRUNQ			1
#define JSWAITING		2
#define JSRUNNING 		3
#define JSRUNNING_USER 		4
#define JSRUNNING_SYS 		5
#define JSINTR			6

#define START_OBJ_PRINT(jsname, jstime, jscount, jstype, jsdetail, jslink)      json_printf(pid_jsonfile, "\n{\"name\":\"%s\", \"time\":\"%f\", \"count\":\"%d\", \"type\":\"%d\", \"detail\":\"%s\", \"link\":\"%s\"", jsname, jstime, jscount, jstype, jsdetail, jslink);

#define START_WAKE_OBJ_PRINT(jsname, jstime, jscount, jstype, jsdetail, jslink, jswlink)      json_printf(pid_jsonfile, "\n{\"name\":\"%s\", \"time\":\"%f\", \"count\":\"%d\", \"type\":\"%d\", \"detail\":\"%s\", \"link\":\"%s\", \"wlink\":\"%s\"", jsname, jstime, jscount, jstype, jsdetail, jslink, jswlink);

#define ENDCURR_OBJ_PRINT json_printf(pid_jsonfile, "},");

#define ENDLAST_OBJ_PRINT json_printf(pid_jsonfile, "}\n");

#define NULL_OBJ_PRINT json_printf(pid_jsonfile, " {}\n");

#define ADD_KIDS_PRINT json_printf(pid_jsonfile, ", \"children\": [ \n");

#define EMPTY_KIDS_PRINT json_printf(pid_jsonfile, ", \"children\": [] \n");

#define END_KIDS_PRINT json_printf(pid_jsonfile, "\n ]");


