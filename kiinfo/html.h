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

extern int font_color;

#define DOC_START if (HTML) printf("<body link=blue vlink=blue alink=blue>\n");
#define TITLE(s) if (HTML) printf("<TITLE>%s</TITLE>\n", s);
#define COLLAPSE_START(tag)										\
	if (HTML) {											\
		collapse_on = TRUE;									\
		printf ("<div class=\"row\">");								\
		printf ("<a href=\"#hide%s\" class=\"hide\" id=\"hide%s\">[+]</a>", tag, tag);		\
		printf ("<a href=\"#show%s\" class=\"show\" id=\"show%s\">[-]</a>\n", tag, tag);	\
		printf ("<div class=\"list\">");							\
	}

#define COLLAPSE_END											\
	if (HTML) {											\
		printf ("</div></div>");								\
		collapse_on = FALSE;									\
	}

#define H1(s) if (HTML) printf("<h1 align=center>%s</h1>\n", s); else printf ("%s\n", s);
#define HR if (HTML) printf("<hr>\n")
#define BR if (HTML) printf("<br>\n")
#define PRE if (HTML) printf("<pre>\n")

#define UL  if (HTML) printf ("<ul>")
#define LI  if (HTML) printf ("<li>")
#define NL  printf("\n")
#define DNL if (dockfile) fprintf (dockfile, "\n"); NL;
#define PNL if (pidfile) fprintf (pidfile, "\n"); NL;

#define NLt if (!HTML) printf ("\n");

#define _A  if (HTML) printf ("</a>")
#define _UL if (HTML) printf ("</ul>")
#define _LI if (HTML) printf ("</li>")
#define _PRE if (HTML) printf ("</pre>")

#define ANM(l) if (HTML) printf ("<a name=""%s""></a>", l )

#define ARF(l,s) if (HTML) printf ("<a href=""#%s"">%s</a>", l, s);  else printf(s)
#define ARFx(l,s) if (HTML)  printf ("<a href=""#%s"">%s</a>", l, s)

#define AER(l, CMD) if (HTML) {printf ("<a href=""%s/%s"" target=""_blank"">", warnurl_dir, l); CMD; _A; }  else CMD; 
#define AERx(l, CMD) if (HTML) {printf ("<a href=""%s/%s"" target=""_blank"">", warnurl_dir, l); CMD; _A; }  

/*  this macro is for warnings */

#define GREEN_TABLE if (HTML) printf("<table border=0 cellpadding=0 cellspacing=0 width=\"100%%\" bgcolor=\"#8CFF8C\"><tr><td>"); else printf ("\n");
#define BLUE_TABLE if (HTML) printf("<table border=0 cellpadding=0 cellspacing=0 width=\"100%%\" bgcolor=\"#CCCCFF\"><tr><td>"); else printf ("\n");
#define ORANGE_TABLE if (HTML) printf("<table border=0 cellpadding=0 cellspacing=0 width=\"100%%\" bgcolor=\"#FFD1A4\"><tr><td>"); else printf ("\n");
#define _TABLE	if (HTML) printf("</td></tr></table>"); else printf("\n\n");

#define SPAN_GREY if (HTML && ((lineno & 1) == 0)) printf("<span style=\"background-color: #EEEEEE\">") 
#define _SPAN	if (HTML && ((lineno & 1) == 0)) printf("</span>");  

#define CAPTION_GREY if (HTML)  printf("<span style=\"background-color: #DDDDDD\">") 
#define _CAPTION if (HTML) printf("</span>\n"); else printf ("\n");

#define FONT_SIZE(size)
/* #define FONT_SIZE(size)  if (HTML) printf("<FONT size=%d>", size); */
#define BLACK_FONT if (HTML && font_color) { printf("</font>"); font_color=0; }
#define RED_FONT if (HTML) {font_color=0xcc0000; printf("<font color=\"#CC0000\">");}
#define BROWN_FONT if (HTML) {font_color=0x996600; printf("<font color=\"#996600\">");}
#define GREEN_FONT if (HTML) {font_color=0x337700; printf("<font color=\"#337700\">");}
#define PURPLE_FONT if (HTML) {font_color=0x990033; printf("<font color=\"#990033\">");}
#define HEAD2(s) if (HTML) printf ("<h2 align=left>%s</h2>", s); else printf(s);
#define HEAD3(s) if (HTML) printf ("<h3 align=left>%s</h3>", s); else printf(s);
#define HEAD4(s) if (HTML) printf ("<h4 align=left>%s</h4>", s); else printf(s);
#define HEAD5(s) if (HTML) printf ("<h5 align=left>%s</h5>", s); else printf(s);
#define ITALIC(s) if (HTML) printf("<I>%s</I>",s); else printf(s);
#define ITALICx(s) if (HTML) printf("<I>%s</I>",s);

#define TEXT(s) if (!HTML) printf(s);
#define TEXTx(s) if (HTML) printf(s);
#define T(s) printf(s)
#define SPACE printf(" ");
#define DSPACE printf("  ");

#define UNDER(s) if (HTML) U(s); else printf (s);
#define UNDERx(s) if (HTML) U(s); 
#define ITALIC_U(s) if (HTML) printf("<U><I>%s</I></U>",s); else printf(s);
#define ITALIC_Ux(s) if (HTML) printf("<U><I>%s</I></U>",s); 


#define STYLE if (HTML) { \
	printf("<style type=\"text/css\">\n"); \
	printf("body {font-family: courier new, courier, serif;}\n"); \
	printf("p {font-family: arial, sans-serif;}\n"); \
	printf("PRE {font-family: monospace, courier new, courier; font-size:12pt; white-space: pre; margin: 0;}\n"); \
	printf("table {padding: 0px 0px 0px 0px;}\n"); \
	printf("th {padding: 0px 4px 0px 4px;}\n"); \
	printf("td {padding: 2px 3px 2px 3px;}\n"); \
		printf (".row {vertical-align: top; height:auto !important;}\n");			\
		printf (".list {display:none;}\n");							\
		printf (".show {display:none;}\n");							\
		printf (".hide:target + .show {display: inline;}\n");					\
		printf (".hide:target {display:none;}\n");						\
		printf (".hide:target ~ .list {display:inline;}\n");					\
		printf ("@media print { .hide, .show { display:none;}}\n");				\
	printf("</style>\n"); \
	}

#define TRACE_TYPE_URL_FIELD24(id)  \
	if (HTML) { \
		char tracename[30];	\
		sprintf (tracename, "%s</A>", kernel_trace_name[id]);	\
		kernel_trace_name[id], \
		(char *)tracename); \
	} else { \
		print("%s", kernel_trace_name[id]); \
	}

#define PID_URL_FIELD8(pid) 										\
	char pidlink[80];										\
	if (dockfile) {											\
		dock_printf("%-8d", (int)pid); 								\
	} else if (kptree && HTML && vis) { 								\
		sprintf (pidlink, "%d</A>", (int)pid); 							\
		printf("<A Href=\"VIS/%d/pid_detail.html\" TARGET=\"kipid vis file\">%-12s", (int)pid, (char *)pidlink);	\
	} else if (cltree && HTML && vis) {								\
		sprintf (pidlink, "%d</A>", (int)pid);							\
		printf("<A Href=\"%s/VIS/%d/pid_detail.html\" TARGET=\"kipid file\">%-12s", globals->subdir, (int)pid, (char *)pidlink);	\
	} else if (kptree && HTML) {									\
                sprintf (pidlink, "%d</A>", (int)pid);                                                  \
                printf("<A Href=\"PIDS/%d\" TARGET=\"kipid file\">%-12s", (int)pid, (char *)pidlink);   \
	} else if (cltree && HTML) {									\
                sprintf (pidlink, "%d</A>", (int)pid);                                                  \
                printf("<A Href=\"%s/PIDS/%d\" TARGET=\"kipid file\">%-12s", globals->subdir, (int)pid, (char *)pidlink);   \
	} else { 											\
		printf("%-8d", (int)pid); 								\
	}

#define PID_URL_FIELD8_R(pid) 										\
	char pidlinkr[80];                                                                               \
	if (kptree && HTML && vis) {                                                                    \
                sprintf (pidlinkr, "%d</A>", (int)pid);                                          \
                printf("<A Href=\"VIS/%d/pid_detail.html\" TARGET=\"kipid vis file\">%12s", (int)pid, (char *)pidlinkr);                         \
        } else if (kptree && HTML) { 											\
		sprintf (pidlinkr, "%d</A>", (int)pid); 							\
		printf("<A Href=\"PIDS/%d\" TARGET=\"kipid file\">%12s", (int)pid, (char *)pidlinkr);	\
	} else { 											\
		printf("%8d", (int)pid); 								\
	}

#define PID_URL_FIELD8_2(pid)                                                                             \
        char pidlink2[30];                                                                               \
        if (kptree && HTML && vis) {                                                                    \
                sprintf (pidlink2, "%d</A>", (int)pid);                                          \
                printf("<A Href=\"VIS/%d/pid_detail.html\" TARGET=\"kipid vis file\">%-12s", (int)pid, (char *)pidlink2);                         \
        } else if (kptree && HTML) {                                                                    \
                sprintf (pidlink2, "%d</A>", (int)pid);                                                  \
                printf("<A Href=\"PIDS/%d\" TARGET=\"kipid file\">%-12s", (int)pid, (char *)pidlink2);   \
        } else {                                                                                        \
                printf("%-8d", (int)pid);                                                               \
        }

#define PID_URL_FIELD8_R_2(pid)                                                                           \
        char pidlinkr2[30];                                                                               \
        if (kptree && HTML && vis) {                                                                    \
                sprintf (pidlinkr2, "%d</A>", (int)pid);                                          \
                printf("<A Href=\"VIS/%d/pid_detail.html\" TARGET=\"kipid vis file\">%12s", (int)pid, (char *)pidlinkr2);                         \
        } else if (kptree && HTML) {                                                                                    \
                sprintf (pidlinkr2, "%d</A>", (int)pid);                                                  \
                printf("<A Href=\"PIDS/%d\" TARGET=\"kipid file\">%12s", (int)pid, (char *)pidlinkr2);    \
        } else {                                                                                        \
                printf("%8d", (int)pid);                                                                \
        }

#define DOCKER_URL_FIELD(id)										\
	if (kptree && HTML) {										\
                printf("<A Href=\"CIDS/%012llx\" TARGET=\"docker file\">%012llx</A>", id, id);		\
	} else {											\
		printf("%012llx", id);									\
	}


#define SERVER_URL_FIELD(serverp)									\
	if (cltree && HTML) {										\
		char serverlink[128];									\
		sprintf (serverlink, "%s</A>", serverp->hostname);					\
		printf("<A Href=\"%s/kp.%s.html\" TARGET=\"kparse file\">%s", serverp->subdir, timestamp, serverlink);	\
	} else {											\
		printf("%s", serverp->hostname);							\
	}

#define SERVER_URL_FIELD_BRACKETS(serverp)									\
	if (cltree && HTML) {											\
		char serverlink[128];											\
		sprintf (serverlink, "%s</A>", serverp->hostname);						\
		printf("[<A Href=\"%s/kp.%s.html\" TARGET=\"kparse file\">%s]", serverp->subdir, timestamp, serverlink);	\
	} else {												\
		printf("[%s]", serverp->hostname);								\
	}													

#define SERVER_URL_FIELD16(serverp)										\
	char serverlink[128];											\
	if (cltree && HTML) {											\
		sprintf (serverlink, "%s</A>", serverp->hostname);						\
		printf("<A Href=\"%s/kp.%s.html\" TARGET=\"kparse file\">%-20s", serverp->subdir, timestamp, serverlink);	\
	} else {												\
		printf("%-16s", serverp->hostname);								\
	}

#define SERVER_URL_FIELD_SECTION(serverp, section)										\
	if (cltree && HTML) {											\
		printf("<A Href=\"%s/kp.%s.html#%s\" TARGET=\"kparse file\">%s</A>", serverp->subdir, timestamp, section, serverp->hostname);	\
	} else {												\
		printf("%s", serverp->hostname);								\
	}

#define SERVER_URL_FIELD_SECTION_BRACKETS(serverp, section)										\
	if (cltree && HTML) {											\
		printf("[<A Href=\"%s/kp.%s.html#%s\" TARGET=\"kparse file\">%s</A>]", serverp->subdir, timestamp, section, serverp->hostname);	\
	} else {												\
		printf("[%s]", serverp->hostname);								\
	}

#define SERVER_URL_FIELD16_SECTION(serverp, section)										\
	char serverlink[128];											\
	if (cltree && HTML) {											\
		sprintf (serverlink, "%s</A>", serverp->hostname);						\
		printf("<A Href=\"%s/kp.%s.html#%s\" TARGET=\"kparse file\">%-20s", serverp->subdir, timestamp, section, serverlink);	\
	} else {												\
		printf("%-16s", serverp->hostname);								\
	}

#define CSV_FIELD(name, label)											\
	if ((cltree || kptree) && HTML) { 									\
		printf("<A Href=\"%s.%s.csv\" TARGET=\"csv file\">%s</A>\n", name, timestamp, label);		\
	}

#define TXT_FIELD(name, label)											\
	if ((cltree || kptree) && HTML) { 									\
		printf("<A Href=\"%s.%s.txt\" TARGET=\"txt file\">%s</A>\n", name, timestamp, label);		\
	}

#define HTML_FIELD(name, label)											\
	if ((cltree || kptree) && HTML) { 									\
		printf("<A Href=\"%s.%s.html\" TARGET=\"html file\">%s</A>\n", name, timestamp, label);		\
	}

#define VISFILE_FIELD(name, label)										\
	if ((cltree || kptree) && HTML) {									\
		printf("<A Href=\"%s.html\" TARGET=\"vis file\">%s</A>\n", name, label);			\
	}
	
#define FILE_FIELD(name, label)											\
	if ((cltree || kptree) && HTML) { 									\
		printf("<A Href=\"%s.%s\" TARGET=\"misc file\">%s</A>\n", name, timestamp, label);		\
	}
