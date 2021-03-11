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
#include <sys/time.h>
#include <sys/errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <linux/kdev_t.h>
#include <err.h>

#include "ki_tool.h"
#include "liki.h"
#include "developers.h"
#include "kd_types.h"
#include "globals.h"
#include "info.h"
#include "oracle.h"
#include "hash.h"
#include "sort.h"
#include "conv.h"
#include "json.h"
#include "vis.h"

int  wtree_build_tree_src(void *, void *);
int  wtree_build_tree_tgt(void *, void *);
int  wtree_build_tree_tgt_src(void *, void *);
int  wtree_build_tree_src_tgt(void *, void *);

#define MAX_WTREE_DEPTH 1
#define MIN_WTREE_PCT 0.01

void
vis_kiall_init()
{
	int ret;
	ret = mkdir("VIS", 0777);
        if (ret && (errno != EEXIST)) {
        	fprintf (stderr, "Unable to make VIS directory, errno %d\n", errno);
                fprintf (stderr, "  Continuing without VIS output\n");
                CLEAR(VIS_FLAG);
        }
        if ((node_csvfile = fopen("node_timeline.csv", "w")) == NULL) {
        	fprintf (stderr, "Unable to open CSV file node_timeline, errno %d\n", errno);
                fprintf (stderr, "  Continuing without VIS output\n");
                CLEAR(VIS_FLAG);
        } else {
                fprintf (node_csvfile, "hostname,timestamp,subdir,host_id,interval,start,end,lcpu_cnt,node_num");
		fprintf (node_csvfile, ",run,sys,user,idle,hirq_sys,hirq_user,hirq_idle");
		fprintf (node_csvfile, ",sirq_sys,sirg_user,sirq_idle,runq_avg,runq_cnt");
		fprintf (node_csvfile, ",max_time,mig,mig_in,mig_out\n");
        }

        if ((server_vis_csvfile = fopen("server_timeline.csv", "w")) == NULL) {
        	fprintf (stderr, "Unable to open CSV file cluster_timeline, errno %d\n", errno);
                fprintf (stderr, "  Continuing without VIS output\n");
                CLEAR(VIS_FLAG);
        } else {
                fprintf(server_vis_csvfile,"hostname,timestamp,path,hostid,interval,start,end,lcpu_cnt");
                fprintf(server_vis_csvfile,",busy_pct,sys_pct,user_pct,idle_pct,hardirq_sys_pct");
		fprintf(server_vis_csvfile,",hardirq_user_pct,hardirq_idle_pct,softirq_sys_pct");
		fprintf(server_vis_csvfile,",softirq_user_pct,softirq_idle_pct");
                fprintf(server_vis_csvfile,",dblidle,lcpu1busy,lcpu2busy,dblbusy");
                fprintf(server_vis_csvfile,",switch_cnt,vol_pct,forced_pct");
                fprintf(server_vis_csvfile,",AvRunqTm,MaxRunqTm,TotRunqTm,RunqCnt,Migrs,LdomMigIn,LdomMigOut");
                fprintf(server_vis_csvfile,",CstateEvts,cstate0,cstate1,cstate2,cstate3,FreqEvts");
                fprintf(server_vis_csvfile,",IO_ps,MB_ps,AvIOsz,AvInFlt,QuTm,SvcTm,wIO_ps");
		fprintf(server_vis_csvfile,",wMB_ps,wAvIOsz,wAvInFlt,wQuTm,wSvcTm,rIO_ps,rMB_ps");
		fprintf(server_vis_csvfile,",rAvIOsz,rAvInFlt,rQuTm,rSvcTm,requeues_ps,barriers_ps");
		fprintf(server_vis_csvfile,",netscalls,netrd,netrdKB,netwr,netwrKB");
                fprintf(server_vis_csvfile,",Events,Buffers,MissedEvents,MissedBufs");
                fprintf(server_vis_csvfile,"\n");
        }
}

void
vis_clparse_init()
{
        int ret;
        ret = mkdir("VIS", 0777);
        if (ret && (errno != EEXIST)) {
                fprintf (stderr, "Unable to make VIS directory (errno %d)\n", errno);
                fprintf (stderr, "  Continuing without VIS output\n");
                CLEAR(VIS_FLAG);
        }
	if (chdir(cwd) == -1) {
		fprintf (stderr, "Unable to change directory to %s (errno %d)\n", cwd, errno);
		fprintf (stderr, "Continuing without VIS output\n");
		CLEAR(VIS_FLAG);
	}
	if ((cluster_vis_csvfile == NULL) && vis)  {
		if ((cluster_vis_csvfile = fopen("cluster_timeline.csv", "a")) == NULL) {
                	fprintf (stderr, "Unable to open CSV file cluster_timeline, errno %d\n", errno);
                	fprintf (stderr, "  Continuing without VIS output\n");
                	CLEAR(VIS_FLAG);
        	} else {
                	fprintf(cluster_vis_csvfile,"hostname,timestamp,path,hostid,interval,start,end,lcpu_cnt");
                	fprintf(cluster_vis_csvfile,",busy_pct,sys_pct,user_pct,idle_pct,hardirq_sys_pct");
                	fprintf(cluster_vis_csvfile,",hardirq_user_pct,hardirq_idle_pct,softirq_sys_pct");
                	fprintf(cluster_vis_csvfile,",softirq_user_pct,softirq_idle_pct");
                	fprintf(cluster_vis_csvfile,",dblidle,lcpu1busy,lcpu2busy,dblbusy");
                	fprintf(cluster_vis_csvfile,",switch_cnt,vol_pct,forced_pct");
                	fprintf(cluster_vis_csvfile,",AvRunqTm,MaxRunqTm,TotRunqTm,RunqCnt,Migrs,LdomMigIn,LdomMigOut");
                	fprintf(cluster_vis_csvfile,",CstateEvts,cstate0,cstate1,cstate2,cstate3,FreqEvts");
                	fprintf(cluster_vis_csvfile,",IO_ps,MB_ps,AvIOsz,AvInFlt,QuTm,SvcTm,wIO_ps");
                	fprintf(cluster_vis_csvfile,",wMB_ps,wAvIOsz,wAvInFlt,wQuTm,wSvcTm,rIO_ps,rMB_ps");
                	fprintf(cluster_vis_csvfile,",rAvIOsz,rAvInFlt,rQuTm,rSvcTm,requeues_ps,barriers_ps");
                	fprintf(cluster_vis_csvfile,",netscalls,netrd,netrdKB,netwr,netwrKB");
                	fprintf(cluster_vis_csvfile,",Events,Buffers,MissedEvents,MissedBufs");
                	fprintf(cluster_vis_csvfile,"\n");
        	}
	} else {
		if ((cluster_vis_csvfile = fopen("cluster_timeline.csv", "a")) == NULL) {
                        fprintf (stderr, "Unable to open CSV file cluster_timeline, errno %d\n", errno);
                        fprintf (stderr, "  Continuing without VIS output\n");
                        CLEAR(VIS_FLAG);
                }
	}
	if (chdir(globals->subdir) == -1) {
		fprintf (stderr, "Unable to change directory to %s", globals->subdir);
		fprintf (stderr, "Current directory is %s", cwd);
	}
	fflush(cluster_vis_csvfile);
	if (system("cat server_timeline.csv | grep -v timestamp >> ../cluster_timeline.csv") == -1) {
		fprintf (stderr, "Unable to create cluster_timeline.csv\n");
	}
}

void
vis_kipid_init()
{
	int ret;
	ret = mkdir("VIS", 0777);
        if (ret && (errno != EEXIST)) {
                fprintf (stderr, "Unable to make VIS directory, errno %d\n", errno);
                fprintf (stderr, "  Continuing without pidvisualize option\n");
                CLEAR(VIS_FLAG);
        }
}

/*
**	How to build a 'Task Wait Dependancy Chart'.  You may need some Excedrin....
**
**	We are going to walk the src and tgt 'who-woke-me' 
**	and 'who-I-woke' lists for tasks responsible for a sleeptime
**	over X% of total sleep, in each list.
**	As we find these tasks, we will add them the root nodes
**	list of 'tasks I want in my chart' and assign them an
**	index number to make the JSON file creation easier.
**	To fill out the JSON format file, we need a list of 'links'
**	and 'nodes'.  The link data comes directly from the 
**	setrq_info_t -> sleep_time field.  The node data is 
**	constructed as we recursively follow the setrq_info hash
**	tables starting from the root task. We do this so that the chart
**	drawn only includes nodes we want to see, and it also allows
**	us to assign an index number to the nodes which is 
**	required in the 'links' portion of the JSON file.
**	We don't want any nodes listed that are not involved
**	in the links...if we allowed this the chart would show 
**	lots of disconnected nodes floating about...information
**	we do not care about from the root nodes perspective.
**
**	A sample JSON file showing the format might help:
**
**
**	{"links":[
**	    {"source":0,"target":1,"value":808},
**	    {"source":1,"target":2,"value":3},
**	    {"source":1,"target":0,"value":16}	
**	],
**	"nodes":[
**	    {"name":"PID 2794", "type":"taskID", "run":33, "runqueue":5,"waitedfor":12963},
**	    {"name":"PID 1832", "type":"taskID", "run":0, "runqueue":0,"waitedfor":0},
**	    {"name":"PID 1875", "type":"taskID", "run":2, "runqueue":3993,"waitedfor":0}
**	]}
**
**	For general JSON format syntax see http://www.json.org
**
**	The key field for the nodes is their 'waitedfor' value.  The more a node is 
**	'waited for' the more likely it is to be a performance bottleneck.  This is 
**	the key visualization of the chart, and the size or color of the node is
**	determined by its 'waitedfor' value.
**
**	For the links, the line width or color can encode the specific wait time,
**	the average wait time, or perhaps the max wait time, between two nodes.
**
*/


/*
** 	A summary of the logic behind searching for nodes and links and assigning depth values
** 	to them as we discover new nodes:
**
** 	To ensure nodes and links are given the lowest depth value relative to the root node, we have to map them
** 	out one level at a time for 'who-we-woke' and 'who-woke-me', assinging depth values as we go.  We
**	cannot simply follow the forward links of who-we-woke and then recursively walk the 'who-woke-me' lists.
**	
**	Starting at level 1, we map out the nodes we woke, and look backwards at who-woke-me. Then go up to level 2,
** 	and repeat...one level of 'who-we-woke' and 'who-woke-me'.  The depth assignment begins to get tricky as
** 	we begin to encounter nodes previously discovered at either an earlier depth, or the same depth.  We should
** 	_never_ encounter a node with a higher depth value than the current depth level we're searching at.
** 	By doing this iterative forward/backward looking wakeup map one level at a time, we are able to produce
** 	a map with lowest value depths for all links and nodes relative tot he root node.
*/



static inline int
unwanted_pid(pid_info_t *pidp)
{
	/* We treat the ICS special.  Its node is added after all others */
	if ((pidp->PID == ICS) || (pidp->PID == 0))
		return 1;

	/* The help should never use front door... 
	** We also need to subtract the kiinfo wait time from
	** the 'total_waited-for' time for a task if we really
	** want to remove the effect of kiinfo interaction
        */

	if (pidp->cmd && (strcmp("kiinfo", pidp->cmd) == 0))
		return 1;
	else
		return 0;
}

/*
** The depth is all relative to the root pid we're evaluating.  It should map out as follows:
**
**     walking back the 'who woke me list'  -> (root) -> walking out the 'who I woke list'
**     N3--(L3)-->N2--(L2)-->N1--(L1)-->(root)--(L1)-->N1--(L2)-->N2--(L3)-->N3--(L4)-->N4
**
** So when we filter to see only up to a depth of '2', all we should see is
**
**                N2--(L2)-->N1--(L1)-->(root)--(L1)-->N1--(L2)-->N2
**
** The depth is adjusted for cases where we encounter a node previously discovered at a
** a different depth level that requires us to adjust the link or node depth value.  This
** happens all the time since we go out the two setrq lists recursively.
*/

int
wtree_build_tree_src_tgt(void *arg0, void *arg1)
{
        setrq_info_t *tgt_setrqp = (setrq_info_t *)arg0;
	var_arg_t *vararg = (var_arg_t *)arg1;
        wait_tree_ptrs_t *wtp = (wait_tree_ptrs_t *)vararg->arg1;
	FILE *pid_wtree_jsonfile = (FILE *)vararg->arg2;
        pid_info_t   *rpidp = wtp->root_pidp;
        pid_info_t   *cpidp = wtp->curr_pidp;
        pid_info_t   *tgt_pidp;

        wait_tree_nodes_t *src_treep;
        wait_tree_nodes_t *tgt_treep;
        sched_info_t *tgt_schedp;
        sched_info_t *rpid_schedp;
        int link_depth = wtp->depth;

        tgt_pidp = GET_PIDP(&globals->pid_hash, tgt_setrqp->PID);
        tgt_schedp = tgt_pidp->schedp;
	rpid_schedp = rpidp->schedp;

        if (unwanted_pid(tgt_pidp))
                return 0;
        if ((!tgt_schedp->sched_stats.T_sleep_time) || (MSECS(tgt_setrqp->sleep_time)/MSECS(tgt_schedp->sched_stats.T_sleep_time) < vpct*0.01))  {
                return 0;
        }
        src_treep = GET_WTREEP(&rpid_schedp->wtree_hash, cpidp->PID);
        tgt_treep = GET_WTREEP(&rpid_schedp->wtree_hash, tgt_setrqp->PID);

        /*
        ** As we look at the list of who we woke, we should only have to deal with two cases.  One is a
        ** node we've never seen before (Ddepth==0) in which case just add the node and link at the
        ** current wtp-depth value.  The second case is that the node was previously discovered at
        ** this same depth. In this case we add the link only.  We do not have to deal with the
        ** case of the target having a lower Ddepth value since the link will have been added in the
        ** in the previous level as that sleepers 'who-woke-me' list was processed.
        */

        if (tgt_treep->Ddepth == 0) {
                link_depth = tgt_treep->Ddepth = wtp->depth;
                if (tgt_pidp->thread_cmd)
                        add_command(&tgt_treep->thr_name,tgt_pidp->thread_cmd);
                if (tgt_pidp->cmd)
                        add_command(&tgt_treep->name,tgt_pidp->cmd);
                if (!tgt_treep->type)
                        tgt_treep->type = TASKID_NODE_TGT;
                if ((tgt_treep->index == 0) && (tgt_treep->PID != rpidp->PID))
                        tgt_treep->index = rpid_schedp->next_index++;
                tgt_treep->infop = &tgt_schedp->sched_stats;
                fprintf(pid_wtree_jsonfile,"{\"source\":%d, \"target\":%d, \"type\":%d, \"value\":%7.1f, \"depth\":%d, \"cnt\":%d, \"srcpid\":%d, \"tgtpid\":%d},\n",
                        src_treep->index,
                        tgt_treep->index,
                        tgt_treep->type,
                        MSECS(tgt_setrqp->sleep_time),
                        link_depth,
                        tgt_setrqp->cnt,
			cpidp->PID,
                        tgt_setrqp->PID);
		if ((src_treep->Ddepth == 0) || (tgt_treep->Ddepth == 0))
			fprintf(stderr,"Depth = 0 in path 1 src=%d tgt=%d wtp_depth=%d\n",src_treep->Ddepth, tgt_treep->Ddepth, wtp->depth);
                return 0;

        } else if (tgt_treep->Ddepth == wtp->depth) {
                link_depth = tgt_treep->Ddepth;
                fprintf(pid_wtree_jsonfile,"{\"source\":%d, \"target\":%d, \"type\":%d, \"value\":%7.1f, \"depth\":%d, \"cnt\":%d, \"srcpid\":%d, \"tgtpid\":%d},\n",
                        src_treep->index,
                        tgt_treep->index,
                        tgt_treep->type,
                        MSECS(tgt_setrqp->sleep_time),
                        link_depth,
                        tgt_setrqp->cnt,
			cpidp->PID,
                        tgt_setrqp->PID);
        }
	if ((src_treep->Ddepth == 0) || (tgt_treep->Ddepth == 0))
                        fprintf(stderr,"Depth = 0 in path 2 src=%d tgt=%d wtp_depth=%d\n",src_treep->Ddepth, tgt_treep->Ddepth, wtp->depth);
        return 0;
}

	
int
wtree_build_tree_src(void *arg0, void *arg1)
{
        setrq_info_t *src_setrqp = (setrq_info_t *)arg0;
	var_arg_t *vararg = (var_arg_t *)arg1;
	wait_tree_ptrs_t *wtp = (wait_tree_ptrs_t *)vararg->arg1;
	FILE *pid_wtree_jsonfile = (FILE *)vararg->arg2;
	pid_info_t   *rpidp = wtp->root_pidp;
        pid_info_t   *cpidp = wtp->curr_pidp;
        pid_info_t   *src_pidp;

        wait_tree_nodes_t *src_treep;
        wait_tree_nodes_t *tgt_treep;
	sched_info_t *src_schedp;
	sched_info_t *rpid_schedp;
	sched_info_t *cpid_schedp;
        
	int link_depth = wtp->depth;

        src_pidp = GET_PIDP(&globals->pid_hash, src_setrqp->PID);
        src_schedp = src_pidp->schedp;
	rpid_schedp = rpidp->schedp;
	cpid_schedp = cpidp->schedp;

	if (unwanted_pid(src_pidp))
		return 0;
        if ((!cpid_schedp->sched_stats.T_sleep_time) || (src_setrqp->sleep_time/(cpid_schedp->sched_stats.T_sleep_time*1.0) < vpct*0.01))
                return 0;
	tgt_treep = GET_WTREEP(&rpid_schedp->wtree_hash, cpidp->PID);
        src_treep = GET_WTREEP(&rpid_schedp->wtree_hash, src_setrqp->PID);

        /*
        ** If we're heading up to a higher level than this current one, the Ddepth on the node we're on
        ** should be greater than 0, but less than the target level.  In this case we just go on to the
        ** next node in the line until we arrive at the desired level...then we start the hunt for new
        ** nodes and links for that level.
        */

	if ((src_treep->Ddepth > 0) && (src_treep->Ddepth > tgt_treep->Ddepth)) {
	    if (src_treep->Ddepth < wtp->depth) {
                wtp->curr_pidp = src_pidp;
                foreach_hash_entry((void **)src_schedp->setrq_src_hash, WPID_HSIZE,
                                        wtree_build_tree_src, setrq_sort_by_sleep_time, npid, (void *)vararg); 
                /* foreach_hash_entry((void **)src_schedp->setrq_src_hash, WPID_HSIZE,
                                        wtree_build_tree_src, NULL, npid, (void *)vararg); */
                wtp->curr_pidp = cpidp;
		if ((src_treep->Ddepth == 0) || (tgt_treep->Ddepth == 0))
                        fprintf(stderr,"Depth = 0 in path 3 src=%d tgt=%d wtp_depth=%d\n",src_treep->Ddepth, tgt_treep->Ddepth, wtp->depth);
                return 0;
	    } else if (src_treep->Ddepth == wtp->depth)
		return 0;
        }

        if (src_treep->Ddepth == 0) {
                link_depth = src_treep->Ddepth = wtp->depth;
		if (src_pidp->thread_cmd)
                	add_command(&src_treep->thr_name,src_pidp->thread_cmd);
       		if (src_pidp->cmd)
                	add_command(&src_treep->name,src_pidp->cmd);
        	if( !src_treep->type)
                	src_treep->type = TASKID_NODE_SRC;
        	if ((src_treep->index == 0) && (src_treep->PID != rpidp->PID))
                	src_treep->index = rpid_schedp->next_index++;
        	src_treep->infop = &src_schedp->sched_stats;
		fprintf(pid_wtree_jsonfile,"{\"source\":%d, \"target\":%d, \"type\":%d, \"value\":%7.1f, \"depth\":%d, \"cnt\":%d, \"srcpid\":%d, \"tgtpid\":%d},\n",
                        src_treep->index,
                        tgt_treep->index,
                        tgt_treep->type,
                        MSECS(src_setrqp->sleep_time),
                        link_depth,
                        src_setrqp->cnt,
                        src_setrqp->PID,
                        cpidp->PID);
		if ((src_treep->Ddepth == 0) || (tgt_treep->Ddepth == 0))
                        fprintf(stderr,"Depth = 0 in path 4 src=%d tgt=%d wtp_depth=%d\n",src_treep->Ddepth, tgt_treep->Ddepth, wtp->depth);
                return 0;
	}

	/*
        ** If the node already exists and its Ddepth is the same as the current depth, then it was likely
        ** just discoverd by another node at the same level.  We simply add the link to it and return.
        ** Or, if we find the source task was previously discovered at a lower level (but not a 0 since this only
        ** occurs for newborn nodes and captured in the above if-case) we just want to print the link info and return.
        **
        ** We can play some node depth fixup here too.  If a node at depth 5 is woken by a node that already
        ** exists at a depth of 2, then the depth 5 node should really become a depth 3 node. I'm not
        ** sure how far this fix-up would propegate if we walk the resulting tree a few times.... the
        ** possibile spider-web of Nth-dimension linkages is endless unless you restrict the depth to 2-3.
        */

        else if ((src_treep->Ddepth == wtp->depth) || (src_treep->Ddepth <= tgt_treep->Ddepth)) {
                if (src_treep->Ddepth <  tgt_treep->Ddepth)
                        link_depth = tgt_treep->Ddepth = src_treep->Ddepth + 1;
                else
                        link_depth = src_treep->Ddepth;
                fprintf(pid_wtree_jsonfile,"{\"source\":%d, \"target\":%d, \"type\":%d, \"value\":%7.1f, \"depth\":%d, \"cnt\":%d, \"srcpid\":%d, \"tgtpid\":%d},\n",
                        src_treep->index,
                        tgt_treep->index,
                        tgt_treep->type,
                        MSECS(src_setrqp->sleep_time),
                        link_depth,
                        src_setrqp->cnt,
                        src_setrqp->PID,
                        cpidp->PID);
		if ((src_treep->Ddepth == 0) || (tgt_treep->Ddepth == 0))
                        fprintf(stderr,"Depth = 0 in path 5 src=%d tgt=%d wtp_depth=%d\n",src_treep->Ddepth, tgt_treep->Ddepth, wtp->depth);
                return 0;
        }

        /*
        ** It should be impossible to discover a node that already exists at a Ddpeth > wtp->depth, since we start
        ** at wtp->depth=1 and work our way up.
        **
        ** So now that we've found all the nodes who woke us at this level, it's time to map out the nodes who 
        ** we wake.  The same node depth fixup tricks will be applied. Again we should never encounter an existing
        ** node at a greater depth than wtp->depth. The routine we call however is non-recursive.  We're just going
        ** to look at the sleepers at this level and that's it....no going backwards multiple levels.  We move forward
        ** with the list of who-woke-me from here.  It'll all work out fine in the end, trust me.....
        */

        wtp->curr_pidp = src_pidp;
        foreach_hash_entry((void **)src_schedp->setrq_tgt_hash, WPID_HSIZE,
                                        wtree_build_tree_src_tgt, setrq_sort_by_sleep_time, npid, (void *)vararg);
        /* foreach_hash_entry((void **)src_schedp->setrq_tgt_hash, WPID_HSIZE,
                                        wtree_build_tree_src_tgt, NULL, npid, (void *)vararg); */
        wtp->curr_pidp = cpidp;
	if ((src_treep->Ddepth == 0) || (tgt_treep->Ddepth == 0))
                        fprintf(stderr,"Depth = 0 in path 6 src=%d tgt=%d wtp_depth=%d\n",src_treep->Ddepth, tgt_treep->Ddepth, wtp->depth);
        return 0;
}



int
wtree_build_tree_tgt_src(void *arg0, void *arg1)
{
        setrq_info_t *src_setrqp = (setrq_info_t *)arg0;
	var_arg_t *vararg = (var_arg_t *)arg1;
        wait_tree_ptrs_t *wtp = (wait_tree_ptrs_t *)vararg->arg1;
	FILE *pid_wtree_jsonfile = (FILE *)vararg->arg2;
        pid_info_t   *rpidp = wtp->root_pidp;
        pid_info_t   *cpidp = wtp->curr_pidp;
        pid_info_t   *src_pidp;

        wait_tree_nodes_t *src_treep;
        wait_tree_nodes_t *tgt_treep;
        sched_info_t *src_schedp;
	sched_info_t *rpid_schedp;
        int link_depth = wtp->depth;

        src_pidp = GET_PIDP(&globals->pid_hash, src_setrqp->PID);
        src_schedp = src_pidp->schedp;
        rpid_schedp = rpidp->schedp;

	if (unwanted_pid(src_pidp))
                return 0;
        if ((!src_schedp->sched_stats.T_sleep_time) || (MSECS(src_setrqp->sleep_time)/MSECS(src_schedp->sched_stats.T_sleep_time) < vpct*0.01))  {
                return 0;
        }
        tgt_treep = GET_WTREEP(&rpid_schedp->wtree_hash, cpidp->PID);
        src_treep = GET_WTREEP(&rpid_schedp->wtree_hash, src_setrqp->PID);

	/*
	** As we look at the list of who woke us, we should only have to deal with two cases.  One is a
	** node we've never seen before (Ddepth==0) in which case just add the node and link at the 
	** current wtp-depth value.  The second case is that the node was previously discovered at 
	** this same depth. In this case we add the link only.  We do not have to deal with the 
	** case of the waker having a lower Ddepth value since the link will have been added in the
	** in the previous level as that wakers 'who-I-woke' list was processed.
	*/

	if (src_treep->Ddepth == 0) {
                link_depth = src_treep->Ddepth = wtp->depth;
                if (src_pidp->thread_cmd)
                        add_command(&src_treep->thr_name,src_pidp->thread_cmd);
                if (src_pidp->cmd)
                        add_command(&src_treep->name,src_pidp->cmd);
                if (!src_treep->type)
                        src_treep->type = TASKID_NODE_TGT;
                if ((src_treep->index == 0) && (src_treep->PID != rpidp->PID))
                        src_treep->index = rpid_schedp->next_index++;
                src_treep->infop = &src_schedp->sched_stats;
                fprintf(pid_wtree_jsonfile,"{\"source\":%d, \"target\":%d, \"type\":%d, \"value\":%7.1f, \"depth\":%d, \"cnt\":%d, \"srcpid\":%d, \"tgtpid\":%d},\n",
                        src_treep->index,
                        tgt_treep->index,
                        tgt_treep->type,
                        MSECS(src_setrqp->sleep_time),
                        link_depth,
                        src_setrqp->cnt,
                        src_setrqp->PID,
                        cpidp->PID);
		if ((src_treep->Ddepth == 0) || (tgt_treep->Ddepth == 0))
                        fprintf(stderr,"Depth = 0 in path 7 src=%d tgt=%d wtp_depth=%d\n",src_treep->Ddepth, tgt_treep->Ddepth, wtp->depth);
                return 0;

        } else if (src_treep->Ddepth == wtp->depth) {
                link_depth = src_treep->Ddepth;
                fprintf(pid_wtree_jsonfile,"{\"source\":%d, \"target\":%d, \"type\":%d, \"value\":%7.1f, \"depth\":%d, \"cnt\":%d, \"srcpid\":%d, \"tgtpid\":%d},\n",
                        src_treep->index,
                        tgt_treep->index,
                        tgt_treep->type,
                        MSECS(src_setrqp->sleep_time),
                        link_depth,
                        src_setrqp->cnt,
                        src_setrqp->PID,
                        cpidp->PID);
        }
	if ((src_treep->Ddepth == 0) || (tgt_treep->Ddepth == 0))
                        fprintf(stderr,"Depth = 0 in path 8 src=%d tgt=%d wtp_depth=%d\n",src_treep->Ddepth, tgt_treep->Ddepth, wtp->depth);
	return 0;
}


int
wtree_build_tree_tgt(void *arg0, void *arg1)
{
	setrq_info_t *tgt_setrqp = (setrq_info_t *)arg0;
	var_arg_t *vararg = (var_arg_t *)arg1;
	wait_tree_ptrs_t *wtp = (wait_tree_ptrs_t *)vararg->arg1;
	FILE *pid_wtree_jsonfile = (FILE *)vararg->arg2;
	pid_info_t   *rpidp = wtp->root_pidp;
	pid_info_t   *cpidp = wtp->curr_pidp;
	pid_info_t   *tgt_pidp;
	
	wait_tree_nodes_t *src_treep;
	wait_tree_nodes_t *tgt_treep;
	sched_info_t *tgt_schedp;
	sched_info_t *rpid_schedp;
	int link_depth = wtp->depth;

	tgt_pidp = GET_PIDP(&globals->pid_hash, tgt_setrqp->PID);
	tgt_schedp = tgt_pidp->schedp;
        rpid_schedp = rpidp->schedp; 

	if (unwanted_pid(tgt_pidp))
                return 0;
	if ((!tgt_schedp->sched_stats.T_sleep_time) || (MSECS(tgt_setrqp->sleep_time)/MSECS(tgt_schedp->sched_stats.T_sleep_time) < vpct*0.01))  {
		return 0;
	}
	src_treep = GET_WTREEP(&rpid_schedp->wtree_hash, cpidp->PID);
        tgt_treep = GET_WTREEP(&rpid_schedp->wtree_hash, tgt_setrqp->PID);


	/* 
	** If we're heading up to a higher level than this current one, the Ddepth on the node we're on
	** should be greater than 0, but less than the target level.  In this case we just go on to the
	** next node in the line until we arrive at the desired level...then we start the hunt for new 
	** nodes and links for that level.
	*/
	
        if ((tgt_treep->Ddepth > 0) && (tgt_treep->Ddepth > src_treep->Ddepth)) {
            if (tgt_treep->Ddepth < wtp->depth) {
                wtp->curr_pidp = tgt_pidp;
                foreach_hash_entry((void **)tgt_schedp->setrq_tgt_hash, WPID_HSIZE,
                                        wtree_build_tree_tgt, setrq_sort_by_sleep_time, npid, (void *)vararg);
                /* foreach_hash_entry((void **)tgt_schedp->setrq_tgt_hash, WPID_HSIZE,
                                        wtree_build_tree_tgt, NULL, npid, (void *)vararg); */
                wtp->curr_pidp = cpidp;
		if ((src_treep->Ddepth == 0) || (tgt_treep->Ddepth == 0))
                        fprintf(stderr,"Depth = 0 in path 9 src=%d tgt=%d wtp_depth=%d\n",src_treep->Ddepth, tgt_treep->Ddepth, wtp->depth);
                return 0;
	    } else if (tgt_treep->Ddepth == wtp->depth)
		return 0;
        }

	/*
	** At each level, if we encounter a node with depth=0, it means it's newly discovered and the depth
	** we should assign is the current depth level ...the wtp->depth value. We fill in the misc 
	** wait_tree_nodes_t info and print the link info in the JSON output file, then return.
	*/

	/*
	** The depth value of the link is determined by the two nodes involved. The link is set to the
	** node min depth+1.  This will usually put the link and target node at the same value, but it
	** could easily be that a node at depth 5 wakes a node at depth 1, so the link appropriately
	** should be "2".  
	*/

	if (tgt_treep->Ddepth == 0) {
                link_depth = tgt_treep->Ddepth = wtp->depth;
		if (tgt_pidp->thread_cmd)
                	add_command(&tgt_treep->thr_name,tgt_pidp->thread_cmd);
        	if (tgt_pidp->cmd)
                	add_command(&tgt_treep->name,tgt_pidp->cmd);
        	if (!tgt_treep->type)
                	tgt_treep->type = TASKID_NODE_TGT;
        	if ((tgt_treep->index == 0) && (tgt_treep->PID != rpidp->PID))
                	tgt_treep->index = rpid_schedp->next_index++;
        	tgt_treep->infop = &tgt_schedp->sched_stats;
        	fprintf(pid_wtree_jsonfile,"{\"source\":%d, \"target\":%d, \"type\":%d, \"value\":%7.1f, \"depth\":%d, \"cnt\":%d, \"srcpid\":%d, \"tgtpid\":%d},\n",
                	src_treep->index,
                	tgt_treep->index,
                	tgt_treep->type,
                	MSECS(tgt_setrqp->sleep_time),
                	link_depth,
                	tgt_setrqp->cnt,
                	cpidp->PID,
                	tgt_setrqp->PID);
		if ((src_treep->Ddepth == 0) || (tgt_treep->Ddepth == 0))
                        fprintf(stderr,"Depth = 0 in path 10 src=%d tgt=%d wtp_depth=%d\n",src_treep->Ddepth, tgt_treep->Ddepth, wtp->depth);
		return 0;
	}

	/*
	** If the node already exists and its Ddepth is the same as the current depth, then it was likely 
	** just discoverd by another node at the same level.  We simply add the link to it and return.
	** Or, if we find the target task was previously discovered at a lower level (but not a 0 since this only
	** occurs for newborn nodes and captured in the above if-case) we just want to print the link info and return.
	**
	** We can play some node depth fixup here too.  If a node at depth 5 is waking a node that already 
	** exists at a depth of 2, then the depth 5 node should really become a depth 3 node. I'm not
	** sure how far this fix-up would propegate if we walk the resulting tree a few times.... the 
	** possibile spider-web of Nth-dimension linkages is endless unless you restrict the depth to 2-3.
	*/

        else if ((tgt_treep->Ddepth == wtp->depth) || (tgt_treep->Ddepth <= src_treep->Ddepth)) {
		if (tgt_treep->Ddepth <  src_treep->Ddepth)
			link_depth = src_treep->Ddepth = tgt_treep->Ddepth + 1;
		else 
			link_depth = tgt_treep->Ddepth; 
		fprintf(pid_wtree_jsonfile,"{\"source\":%d, \"target\":%d, \"type\":%d, \"value\":%7.1f, \"depth\":%d, \"cnt\":%d, \"srcpid\":%d, \"tgtpid\":%d},\n",
                        src_treep->index,
                        tgt_treep->index,
                        tgt_treep->type,
                        MSECS(tgt_setrqp->sleep_time),
                        link_depth,
                        tgt_setrqp->cnt,
                        cpidp->PID,
                        tgt_setrqp->PID);
		if ((src_treep->Ddepth == 0) || (tgt_treep->Ddepth == 0))
                        fprintf(stderr,"Depth = 0 in path 11 src=%d tgt=%d wtp_depth=%d\n",src_treep->Ddepth, tgt_treep->Ddepth, wtp->depth);
                return 0;
	}

	/*
	** It should be impossible to discover a node that already exists at a Ddpeth > wtp->depth, since we start
	** at wtp->depth=1 and work our way up. 
	**
	** So now that we've found all the nodes we wake at this level, it's time to map out the nodes who wake us
	** up.  The same node depth fixup tricks will be applied. Again we should never encounter an existing
	** node at a greater depth than wtp->depth. The routine we call however is non-recursive.  We're just going
	** to look at the wakers at this level and that's it....no gong backwards multiple levels.  We move forward 
	** with the list of who-we-woke from here.  It'll all work out fine in the end, trust me.....
	*/

	wtp->curr_pidp = tgt_pidp;
        foreach_hash_entry((void **)tgt_schedp->setrq_src_hash, WPID_HSIZE,
                                        wtree_build_tree_tgt_src, setrq_sort_by_sleep_time, npid, (void *)vararg);
        /* foreach_hash_entry((void **)tgt_schedp->setrq_src_hash, WPID_HSIZE,
                                        wtree_build_tree_tgt_src, NULL, npid, (void *)vararg); */
	wtp->curr_pidp = cpidp;
	if ((src_treep->Ddepth == 0) || (tgt_treep->Ddepth == 0))
                        fprintf(stderr,"Depth = 0 in path 12 src=%d tgt=%d wtp_depth=%d\n",src_treep->Ddepth, tgt_treep->Ddepth, wtp->depth);
	return 0;
} 


int
wtree_build_nodelist(void *arg0, void *arg1)
{
        wait_tree_nodes_t *wtnp = (wait_tree_nodes_t *)arg0;
	var_arg_t *vararg = (var_arg_t *)arg1;
        wait_tree_ptrs_t *wtp = (wait_tree_ptrs_t *)vararg->arg1;
	FILE *pid_wtree_jsonfile = (FILE *)vararg->arg2;

	char *shortnamep;
        if (!wtnp->name) {
                fprintf(stderr,"Empty wtnp entry pid=%d\n", wtnp->PID);
		return 0;
	}
	sched_stats_t *statsp = (sched_stats_t *)wtnp->infop;
	shortnamep = wtnp->name;
	if (!(strchr(wtnp->name,'[')) && strrchr(wtnp->name,'/'))
		shortnamep = strrchr(wtnp->name,'/')+1;

	fprintf(pid_wtree_jsonfile,"{\"name\":\"PID %d\",\"cmd\":\"%s\", \"thr_cmd\":\"%s\",\"type\":%d, \"run\":%7.1f, \"runq\":%7.1f, \"sleep_time\":%7.1f, \"waitedfor\":%7.1f, \"depth\":%d, \"wlink\":\"../../VIS/%d/pid_detail.html\"},\n",
                wtnp->PID,
                shortnamep,
                wtnp->thr_name,
		wtnp->type,
                MSECS(statsp->T_run_time),
                MSECS(statsp->T_runq_time),
		MSECS(statsp->T_sleep_time),
                MSECS(statsp->T_total_waited4_time),
		wtnp->Ddepth,
		wtnp->PID);
	return 0;
}

void
wtree_build(pid_info_t *pidp, FILE *pid_wtree_jsonfile)
{
	sched_info_t *schedp;
	setrq_info_t *setrqp;
	setrq_info_t *ics_setrqp;
	var_arg_t vararg;
	int   i,depth=0;

	wait_tree_ptrs_t wtree_ptrs;
	wait_tree_nodes_t *root_treep;

	if ((!vis) || unwanted_pid(pidp))
		return;

	wtree_ptrs.root_pidp = pidp;
	wtree_ptrs.curr_pidp = pidp;
	wtree_ptrs.depth = 0;
	schedp = pidp->schedp;

	ics_setrqp =  GET_SETRQP(&schedp->setrq_src_hash, ICS);
	root_treep = GET_WTREEP(&schedp->wtree_hash, pidp->PID);
	root_treep->index = schedp->next_index++;
	if (pidp->thread_cmd)
                add_command(&root_treep->thr_name,pidp->thread_cmd);
        if (pidp->cmd)
                 add_command(&root_treep->name,pidp->cmd);
        root_treep->type = TASKID_NODE;
	root_treep->Ddepth = 1;
        root_treep->infop = &schedp->sched_stats;

	fprintf(pid_wtree_jsonfile,"{\n\"links\":[\n");

	vararg.arg1 = (void *)&wtree_ptrs;
	vararg.arg2 = pid_wtree_jsonfile;
    	for( wtree_ptrs.depth = 2; wtree_ptrs.depth <= vdepth+1; wtree_ptrs.depth++) {
        	wtree_ptrs.curr_pidp = pidp;
		foreach_hash_entry((void **)schedp->setrq_tgt_hash, WPID_HSIZE,
                                        wtree_build_tree_tgt, setrq_sort_by_sleep_time, npid, (void *)&vararg); 
		/* foreach_hash_entry((void **)schedp->setrq_tgt_hash, WPID_HSIZE,
                                        wtree_build_tree_tgt, NULL, npid, (void *)&vararg); */
		wtree_ptrs.curr_pidp = pidp;
		foreach_hash_entry((void **)schedp->setrq_src_hash, WPID_HSIZE,
                                        wtree_build_tree_src, setrq_sort_by_sleep_time, npid, (void *)&vararg);
		/* foreach_hash_entry((void **)schedp->setrq_src_hash, WPID_HSIZE, 
                                        wtree_build_tree_src, NULL, npid, (void *)&vararg); */
        }

	/* We add the link to the ICS waker last so we can terminate the line w/o the comma... */

	fprintf(pid_wtree_jsonfile,"{\"source\":%d, \"target\":%d, \"value\":%7.1f, \"depth\":%d, \"cnt\":%d}\n",
                schedp->next_index,  /* no increment so we can use the same number for the ICS node added below.  */
                0,
                MSECS(ics_setrqp->sleep_time),
		1,
		ics_setrqp->cnt);
	fprintf(pid_wtree_jsonfile,"],\n");

	/* now build or add on the 'nodes' portion of the JSON file. */

        fprintf(pid_wtree_jsonfile,"\"nodes\":[\n");

	foreach_hash_entry((void **)schedp->wtree_hash, WTREE_HSIZE,
                                        wtree_build_nodelist, NULL, 0x7fffffff, (void *)&vararg);

	/* Similar to the last 'links' line above, we add the ICS node information */

	fprintf(pid_wtree_jsonfile,"{\"name\":\"PID -1 (ICS)\",\"cmd\":\"ICS\", \"thr_cmd\":\"ICS\", \"type\":\"taskID_SRC\", \"run\":0, \"runq\":0, \"waitedfor\":%7.1f, \"depth\":%d, \"wlink\":\"../../VIS/-1/pid_detail.html\"}\n",
                MSECS(ics_setrqp->sleep_time),
		1);
	fprintf(pid_wtree_jsonfile,"]\n}");
	return;
}

int print_vis_task_interval_data();

void
vis_interval_processing(uint64 hrtime)
{
        /* heavily leveraged from the cl_perserver_csv() routine */
	/* Adding task level timeline stats at the default interval as well */
	/* as detailed scheduling timeline data for drilldown charts.  */ 

        server_info_t   *serverp = globals;     /* globals points to current server_info_t */
        int i,j,lcpu1,lcpu2,ldom;
        pcpu_info_t *pcpuinfop;
        cpu_info_t *cpuinfop, *cpu1infop, *cpu2infop;
        sched_info_t *gschedp,*cschedp, *curr_schedp, *prev_schedp;
        sched_stats_t *gstatp,*cstatp, *curr_lstatp, *prev_lstatp, *curr_statp, *prev_statp;
        ldom_info_t  *prev_ldominfop, *curr_ldominfop;
        runq_info_t *rqinfop, *curr_rqinfop, *prev_rqinfop;
        power_info_t *powerp, *curr_powerp, *prev_powerp;
        hc_info_t *hcinfop;
        uint64 cstate_total_time = 0;
        struct iostats *iostatsp, *curr_iostatsp, *prev_iostatsp;

        if ((prev_int_serverp == NULL) || (curr_int_serverp == NULL)) {
                prev_int_serverp  = calloc( 1, sizeof(server_info_t));
                curr_int_serverp  = calloc( 1, sizeof(server_info_t));
        }

	update_cpu_times(interval_end);
        calc_global_cpu_stats(serverp, NULL);

        gschedp = GET_ADD_SCHEDP(&serverp->schedp);
        gstatp = &gschedp->sched_stats;

        prev_schedp = GET_ADD_SCHEDP(&prev_int_serverp->schedp);
        prev_statp = &prev_schedp->sched_stats;

        curr_schedp = GET_ADD_SCHEDP(&curr_int_serverp->schedp);
        curr_statp = &curr_schedp->sched_stats;

        curr_rqinfop = GET_ADD_RQINFOP(&curr_schedp->rqinfop);
        prev_rqinfop = GET_ADD_RQINFOP(&prev_schedp->rqinfop);

        curr_powerp = GET_POWERP(curr_int_serverp->powerp);
        prev_powerp = GET_POWERP(prev_int_serverp->powerp);

        curr_iostatsp = &curr_int_serverp->iostats[0];
        prev_iostatsp = &prev_int_serverp->iostats[0];

        /* We harverst the ldom cpu stats at every interval by looping thru all CPUs */

        for (i=0;i<MAXCPUS;i++) {
                if (cpuinfop = FIND_CPUP(serverp->cpu_hash, i)) {
                        cschedp =  GET_ADD_SCHEDP(&cpuinfop->schedp);
                        cstatp = &cschedp->sched_stats;
                        prev_ldominfop = GET_LDOMP(&prev_int_serverp->ldom_hash, cpuinfop->ldom);
                        curr_ldominfop = GET_LDOMP(&curr_int_serverp->ldom_hash, cpuinfop->ldom);
                        if (i == 0) {
                                 curr_ldominfop->ncpus = 0;
                        }
                        curr_ldominfop->ncpus++;
                        curr_lstatp = &curr_ldominfop->sched_stats;
                        prev_lstatp = &prev_ldominfop->sched_stats;
			for (j = 0; j < N_TIME_STATS; j++) 
				curr_lstatp->time[j] = cstatp->time[j];

                        rqinfop = GET_ADD_RQINFOP(&cschedp->rqinfop);
                        ldom = cpuinfop->ldom;
                        curr_int_ldrq[ldom].total_time += rqinfop->total_time;
                        if (rqinfop->max_time_int > ldrq[ldom].max_time_int)
                                ldrq[ldom].max_time_int = rqinfop->max_time_int;
                        if (rqinfop->max_time_int > curr_rqinfop->max_time_int)
                                curr_rqinfop->max_time_int = rqinfop->max_time_int;
                        curr_int_ldrq[ldom].cnt += rqinfop->cnt;
                        curr_int_ldrq[ldom].migrations += rqinfop->migrations;
                        curr_int_ldrq[ldom].ldom_migrations_in += rqinfop->ldom_migrations_in;
                        curr_int_ldrq[ldom].ldom_migrations_out += rqinfop->ldom_migrations_out;
                }
        }

        /* Now let's continue tallying up the various server-wide stats for this interval. */

	for (j = 0; j < N_TIME_STATS; j++) 
		curr_statp->time[j] = gstatp->time[j];

        curr_int_serverp->ht_double_idle =  serverp->ht_double_idle;
        curr_int_serverp->ht_lcpu1_busy = serverp->ht_lcpu1_busy;
        curr_int_serverp->ht_lcpu2_busy = serverp->ht_lcpu2_busy;
        curr_int_serverp->ht_double_busy = serverp->ht_double_busy;

        curr_statp->C_switch_cnt = gstatp->C_switch_cnt;
        curr_statp->C_sleep_cnt =  gstatp->C_sleep_cnt;
        curr_statp->C_preempt_cnt = gstatp->C_preempt_cnt;

        rqinfop = GET_ADD_RQINFOP(&gschedp->rqinfop);
        curr_rqinfop->max_time_int = rqinfop->max_time_int;
        curr_rqinfop->total_time = rqinfop->total_time;
        curr_rqinfop->cnt = rqinfop->cnt;
        curr_rqinfop->migrations = rqinfop->migrations;
        curr_rqinfop->ldom_migrations_in = rqinfop->ldom_migrations_in;
        curr_rqinfop->ldom_migrations_out = rqinfop->ldom_migrations_out;

        powerp = GET_POWERP(serverp->powerp);
        curr_powerp->cstate_times[0] = powerp->cstate_times[0];
        curr_powerp->cstate_times[1] = powerp->cstate_times[1];
        curr_powerp->cstate_times[2] = powerp->cstate_times[2];
        curr_powerp->cstate_times[3] = powerp->cstate_times[3];
        curr_powerp->power_freq_cnt = powerp->power_freq_cnt;

        /* now the iostats */

        calc_io_totals(&serverp->iostats[0], NULL);

        i = IOTOT;
        while (i >= 0) {
                iostatsp = &serverp->iostats[i];
                curr_iostatsp = &curr_int_serverp->iostats[i];

                curr_iostatsp->compl_cnt = iostatsp->compl_cnt;
                curr_iostatsp->sect_xfrd = iostatsp->sect_xfrd;
                curr_iostatsp->cum_async_inflight = iostatsp->cum_async_inflight;
                curr_iostatsp->cum_sync_inflight = iostatsp->cum_sync_inflight;
                curr_iostatsp->cum_iowait = iostatsp->cum_iowait;
                curr_iostatsp->cum_ioserv = iostatsp->cum_ioserv;
                curr_iostatsp->requeue_cnt = iostatsp->requeue_cnt;
                curr_iostatsp->barrier_cnt = iostatsp->barrier_cnt;
                i--;
        }

	curr_int_serverp->netstats.syscall_cnt = serverp->netstats.syscall_cnt;
	curr_int_serverp->netstats.rd_cnt = serverp->netstats.rd_cnt;
	curr_int_serverp->netstats.rd_bytes = serverp->netstats.rd_bytes;
	curr_int_serverp->netstats.wr_cnt = serverp->netstats.wr_cnt;
	curr_int_serverp->netstats.wr_bytes = serverp->netstats.wr_bytes;
/*
        csv_printf(cluster_csvfile, ",%8d,%9.1f,%11.1f,%9.1f,%11.1f",
                serverp->netstats.syscall_cnt,
                serverp->netstats.rd_cnt / serverp->total_secs,
                (serverp->netstats.rd_bytes / 1024) / serverp->total_secs,
                serverp->netstats.wr_cnt / serverp->total_secs,
                (serverp->netstats.wr_bytes / 1024) / serverp->total_secs);
*/

        curr_int_serverp->total_events = serverp->total_events;
        curr_int_serverp->total_buffers =  serverp->total_buffers;
        curr_int_serverp->missed_events = serverp->missed_events;
        curr_int_serverp->missed_buffers = serverp->missed_buffers;


        /* Print the interval data to the respective csv files */
        print_vis_interval_data();

	/* Print the per-task interval data to the per-task CSV files */
	print_vis_task_interval_data();

        /* 
	** We assign curr to prev for the LDOM related metrics, 
	** and set up for the next interval 
	*/

        for (i=0;i<MAXCPUS;i++) {
                if (cpuinfop = FIND_CPUP(serverp->cpu_hash, i)) {
                        prev_ldominfop = GET_LDOMP(&prev_int_serverp->ldom_hash, cpuinfop->ldom);
                        curr_ldominfop = GET_LDOMP(&curr_int_serverp->ldom_hash, cpuinfop->ldom);
                        ldom = cpuinfop->ldom;
                        curr_lstatp = &curr_ldominfop->sched_stats;
                        prev_lstatp = &prev_ldominfop->sched_stats;

                        prev_lstatp->T_run_time = curr_lstatp->T_run_time;
                        prev_lstatp->T_sys_time = curr_lstatp->T_sys_time;
                        prev_lstatp->T_user_time = curr_lstatp->T_user_time;
                        prev_lstatp->T_idle_time = curr_lstatp->T_idle_time;
                        prev_lstatp->T_hardirq_sys_time = curr_lstatp->T_hardirq_sys_time;
                        prev_lstatp->T_hardirq_user_time = curr_lstatp->T_hardirq_user_time;
                        prev_lstatp->T_hardirq_idle_time = curr_lstatp->T_hardirq_idle_time;
                        prev_lstatp->T_softirq_sys_time = curr_lstatp->T_softirq_sys_time;
                        prev_lstatp->T_softirq_user_time = curr_lstatp->T_softirq_user_time;
                        prev_lstatp->T_softirq_idle_time = curr_lstatp->T_softirq_idle_time;

                        prev_int_ldrq[ldom].total_time = curr_int_ldrq[ldom].total_time;
                        prev_int_ldrq[ldom].cnt = curr_int_ldrq[ldom].cnt;
                        prev_int_ldrq[ldom].max_time_int = curr_int_ldrq[ldom].max_time_int;
                        prev_int_ldrq[ldom].migrations = curr_int_ldrq[ldom].migrations;
                        prev_int_ldrq[ldom].ldom_migrations_in = curr_int_ldrq[ldom].ldom_migrations_in;
                        prev_int_ldrq[ldom].ldom_migrations_out = curr_int_ldrq[ldom].ldom_migrations_out;
                        cpuinfop->schedp->rqinfop->max_time_int = 0;
                        ldrq[ldom].max_time_int = 0;
			
                }
        }
	/* Don't forget to reset the global max_time_int value...   */
	rqinfop = GET_ADD_RQINFOP(&gschedp->rqinfop);
	rqinfop->max_time_int = 0;

        /* Now assign curr to prev for the rest of the server-wide metrics */

	for (i = 0; i < N_TIME_STATS; i++) {
		prev_statp->time[i] = curr_statp->time[i];
	}

        prev_int_serverp->ht_total_time = curr_int_serverp->ht_total_time;
        prev_int_serverp->ht_double_idle = curr_int_serverp->ht_double_idle;
        prev_int_serverp->ht_lcpu1_busy = curr_int_serverp->ht_lcpu1_busy;
        prev_int_serverp->ht_lcpu2_busy = curr_int_serverp->ht_lcpu2_busy;
        prev_int_serverp->ht_double_busy = curr_int_serverp->ht_double_busy;

        prev_statp->C_switch_cnt = curr_statp->C_switch_cnt;
        prev_statp->C_sleep_cnt = curr_statp->C_sleep_cnt;
        prev_statp->C_preempt_cnt = curr_statp->C_preempt_cnt;

        prev_rqinfop->total_time = curr_rqinfop->total_time;
        prev_rqinfop->cnt = curr_rqinfop->cnt;
        prev_rqinfop->migrations = curr_rqinfop->migrations;
        prev_rqinfop->ldom_migrations_in = curr_rqinfop->ldom_migrations_in;
        prev_rqinfop->ldom_migrations_out = curr_rqinfop->ldom_migrations_out;
        prev_rqinfop->max_time_int = curr_rqinfop->max_time_int = 0;

        prev_powerp->cstate_times[0] = curr_powerp->cstate_times[0];
        prev_powerp->cstate_times[1] = curr_powerp->cstate_times[1];
        prev_powerp->cstate_times[2] = curr_powerp->cstate_times[2];
        prev_powerp->cstate_times[3] = curr_powerp->cstate_times[3];
        prev_powerp->power_freq_cnt = curr_powerp->power_freq_cnt;

        i = IOTOT;
        while (i >= 0) {
                curr_iostatsp = &curr_int_serverp->iostats[i];
                prev_iostatsp = &prev_int_serverp->iostats[i];

                prev_iostatsp->compl_cnt = curr_iostatsp->compl_cnt;
                prev_iostatsp->sect_xfrd = curr_iostatsp->sect_xfrd;
                prev_iostatsp->cum_async_inflight = curr_iostatsp->cum_async_inflight;
                prev_iostatsp->cum_sync_inflight = curr_iostatsp->cum_sync_inflight;
                prev_iostatsp->cum_iowait = curr_iostatsp->cum_iowait;
                prev_iostatsp->cum_ioserv = curr_iostatsp->cum_ioserv;
                prev_iostatsp->requeue_cnt = curr_iostatsp->requeue_cnt;
                prev_iostatsp->barrier_cnt = curr_iostatsp->barrier_cnt;

                i--;
        }

        prev_int_serverp->netstats.syscall_cnt = curr_int_serverp->netstats.syscall_cnt;
        prev_int_serverp->netstats.rd_cnt = curr_int_serverp->netstats.rd_cnt;
        prev_int_serverp->netstats.rd_bytes = curr_int_serverp->netstats.rd_bytes;
        prev_int_serverp->netstats.wr_cnt = curr_int_serverp->netstats.wr_cnt;
        prev_int_serverp->netstats.wr_bytes = curr_int_serverp->netstats.wr_bytes;

        prev_int_serverp->total_events = curr_int_serverp->total_events;
        prev_int_serverp->total_buffers = curr_int_serverp->total_buffers;
        prev_int_serverp->missed_events = curr_int_serverp->missed_events;
        prev_int_serverp->missed_buffers = curr_int_serverp->missed_buffers;

}

void
cpu_interval_processing(uint64 hrtime)
{
        return;
}


int
print_task_tlinedata(void *arg1, void *arg2)
{
	pid_info_t *pidp = (pid_info_t *)arg1;
	int pid_timeline_csv_fd = -1;
	char pid_timeline_buffer[1024];

	if (pidp == NULL) return 0;

	if (!vis) return 0;

        char vis_dir[20];
	char pidtl_fname[32];
	int i, ret=0, add_hdr=0;
	uint64 total_time;
	sched_info_t *schedp;
	sched_stats_t *statp;
	iostats_t *rstatp, *wstatp, *tstatp;
	float run_per_csw=0.0;

	schedp = GET_ADD_SCHEDP(&pidp->schedp);
	statp = &schedp->sched_stats;

	sprintf (vis_dir, "VIS/%d", (int)pidp->PID);
	sprintf (pidtl_fname, "VIS/%d/pid_timeline.csv", (int)pidp->PID);
	ret = mkdir(vis_dir, 0777);
	if (ret && (errno == EEXIST)) {
                        /* the common case....dir exists which implies file exists with headers  */
			/* We just fopen the file and append CSV data...headers are already there */
        } else if (ret == 0) {
		/* Set a flag that tells us we need to add the header fields before appending CSV data */
		add_hdr = 1;
	} else {
                fprintf (stderr, "Unable to make VIS/_pid_ directory, errno %d\n", errno);
		fprintf (stderr, "  Continuing without PID output\n");
                CLEAR(VIS_FLAG);
		return 0;
	}

        if ((pid_timeline_csv_fd = open(pidtl_fname, O_CREAT | O_WRONLY | O_APPEND, 0777)) < 0) {
                fprintf (stderr, "Unable to open PID Timeline CSV %s for append, errno %d\n", pidtl_fname, pid_timeline_csv_fd);
                fprintf (stderr, "  Continuing without PID output\n");
		CLEAR(VIS_FLAG);
		return 0;
        }

	statp->time[IRQ_TIME] = 0;
	for (i=IRQ_BEGIN; i <= IRQ_END; i++)
		statp->time[IRQ_TIME] += statp->time[i];
        total_time = statp->T_sys_time + statp->T_user_time + statp->T_runq_time + statp->T_sleep_time + statp->T_irq_time;

	tstatp = &pidp->iostats[IO_TOTAL];
        rstatp = &pidp->iostats[IO_READ];
        wstatp = &pidp->iostats[IO_WRITE];

	if (statp->T_run_time && statp->C_switch_cnt)
		run_per_csw = SECS((statp->T_run_time * 1.0) / statp->C_switch_cnt);

	if (add_hdr) {
		sprintf(pid_timeline_buffer, "hostname,timestamp,subdir,server_id,interval,start,end,pid,syscalls,runtime,systime,usertime,runqtime,sleeptime,irqtime,totaltime,stealtime,switch_cnt,sleep_cnt,preempt_cnt,wakeup_cnt,run_per_csw,migr,nodemigr,totalio,readio,writeio\n");
		ret = write (pid_timeline_csv_fd, pid_timeline_buffer, strlen(pid_timeline_buffer));
	}

	sprintf(pid_timeline_buffer, "%s,%s,%s,%d,%d,%.06f,%.06f,%d,%d,",
                globals->hostname,
		timestamp,
                globals->subdir,
                globals->server_id,
                vint,
                SECS(interval_start - start_time),
                SECS(interval_end - start_time),	
		(int)pidp->PID,
		pidp->syscall_cnt);
	ret = write (pid_timeline_csv_fd, pid_timeline_buffer, strlen(pid_timeline_buffer));

        sprintf(pid_timeline_buffer, "%7.6f,%7.6f,%7.6f,%7.6f,%7.6f,%7.6f,%7.6f,%7.6f,%d,%d,%d,%d,%7.6f,%d,%d,%d,%d,%d\n",
                SECS(statp->T_run_time),
                SECS(statp->T_sys_time),
                SECS(statp->T_user_time),
                SECS(statp->T_runq_time),
                SECS(statp->T_sleep_time),
                SECS(statp->T_irq_time),
		SECS(total_time),
                SECS(statp->T_stealtime),
                statp->C_switch_cnt,
                statp->C_sleep_cnt,
                statp->C_preempt_cnt,
                statp->C_wakeup_cnt,
                run_per_csw,
                schedp->cpu_migrations,
                schedp->ldom_migrations,
		rstatp->compl_cnt + wstatp->compl_cnt,
		rstatp->compl_cnt,
		wstatp->compl_cnt);
	ret = write (pid_timeline_csv_fd, pid_timeline_buffer, strlen(pid_timeline_buffer));
	
	close(pid_timeline_csv_fd);
}

int
print_vis_task_interval_data()
{
	foreach_hash_entry_mt((void **)globals->pid_hash, PID_HASHSZ, print_task_tlinedata, NULL, 0, NULL);
}

void
print_vis_interval_data()
{
        int i, ldom_num;
        ldom_info_t *cldip, *pldip;
        sched_info_t *curr_schedp, *prev_schedp;
        sched_stats_t *curr_lstatp, *prev_lstatp, *curr_statp, *prev_statp;
        uint64 ht_total_time, ht_double_idle, ht_lcpu1_busy, ht_lcpu2_busy, ht_double_busy;
        uint64 curr_total_time = 0, prev_total_time = 0;
        runq_info_t *rqinfop, *curr_rqinfop, *prev_rqinfop;
        power_info_t *curr_powerp, *prev_powerp;
        uint64 rq_tt, cstate_total_time = 0;
        uint64 irq_time = 0, busy_time = 0, total_time = 0;
        struct iostats *curr_iostatsp, *prev_iostatsp;

        prev_schedp = GET_ADD_SCHEDP(&prev_int_serverp->schedp);
        prev_statp = &prev_schedp->sched_stats;

        curr_schedp = GET_ADD_SCHEDP(&curr_int_serverp->schedp);
        curr_statp = &curr_schedp->sched_stats;

        curr_rqinfop = GET_ADD_RQINFOP(&curr_schedp->rqinfop);
        prev_rqinfop = GET_ADD_RQINFOP(&prev_schedp->rqinfop);

        curr_powerp = GET_POWERP(curr_int_serverp->powerp);
        prev_powerp = GET_POWERP(prev_int_serverp->powerp);

        /*
        ** We first print the per-node/ldom CPU metrics to the node_csvfile
        */

        for (ldom_num =0;ldom_num<MAXLDOMS;ldom_num++) {
                if (( pldip = FIND_LDOMP(prev_int_serverp->ldom_hash, ldom_num)) &&
                        ( cldip = FIND_LDOMP(curr_int_serverp->ldom_hash, ldom_num))) {

                        curr_lstatp = &cldip->sched_stats;
                        prev_lstatp = &pldip->sched_stats;

			curr_lstatp->time[IRQ_TIME] = prev_lstatp->time[IRQ_TIME] = 0;
			for (i = IRQ_BEGIN; i <= IRQ_END; i++) {
				curr_lstatp->time[IRQ_TIME] += curr_statp->time[i];
				prev_lstatp->time[IRQ_TIME] += prev_statp->time[i];
			}

                        curr_total_time = curr_lstatp->T_idle_time + curr_lstatp->T_sys_time + curr_lstatp->T_user_time + curr_lstatp->T_irq_time;
                        prev_total_time = prev_lstatp->T_idle_time + prev_lstatp->T_sys_time + prev_lstatp->T_user_time + prev_lstatp->T_irq_time;

                        total_time = curr_total_time - prev_total_time;

                        rq_tt = curr_int_ldrq[ldom_num].total_time - prev_int_ldrq[ldom_num].total_time;
                        if (node_csvfile) {
                                fprintf ( node_csvfile, "%s,%s,%s,%d,%d,%.06f,%.06f,%d,%d,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.02f,%lld,%lld,%d,%d,%d\n",
                                globals->hostname,
				timestamp,
                                globals->subdir,
                                globals->server_id,
                                vint,
                                SECS(interval_start - start_time),
                                SECS(interval_end - start_time),
				globals->nlcpu,
                                ldom_num,
                                ((curr_lstatp->T_run_time - prev_lstatp->T_run_time) * 100.0) / total_time,
                                ((curr_lstatp->T_sys_time - prev_lstatp->T_sys_time) * 100.0) / total_time,
                                ((curr_lstatp->T_user_time - prev_lstatp->T_user_time) * 100.0) / total_time,
                                ((curr_lstatp->T_idle_time - prev_lstatp->T_idle_time) * 100.0) / total_time,
                                ((curr_lstatp->T_hardirq_sys_time - prev_lstatp->T_hardirq_sys_time) * 100.0) / total_time,
                                ((curr_lstatp->T_hardirq_user_time - prev_lstatp->T_hardirq_user_time) * 100.0) / total_time,
                                ((curr_lstatp->T_hardirq_idle_time - prev_lstatp->T_hardirq_idle_time) * 100.0) / total_time,
                                ((curr_lstatp->T_softirq_sys_time - prev_lstatp->T_softirq_sys_time) * 100.0) / total_time,
                                ((curr_lstatp->T_softirq_user_time - prev_lstatp->T_softirq_user_time) * 100.0) / total_time,
                                ((curr_lstatp->T_softirq_idle_time - prev_lstatp->T_softirq_idle_time) * 100.0) / total_time,
                                (rq_tt * 1.0 / (curr_int_ldrq[ldom_num].cnt - prev_int_ldrq[ldom_num].cnt)),
                                curr_int_ldrq[ldom_num].cnt - prev_int_ldrq[ldom_num].cnt,
                                curr_int_ldrq[ldom_num].max_time_int,
                                curr_int_ldrq[ldom_num].migrations - prev_int_ldrq[ldom_num].migrations,
                                curr_int_ldrq[ldom_num].ldom_migrations_in - prev_int_ldrq[ldom_num].ldom_migrations_in,
                                curr_int_ldrq[ldom_num].ldom_migrations_out - prev_int_ldrq[ldom_num].ldom_migrations_out);
                        }
                }
        }

        /*
        ** Now we'll print the server-wide metrics to the server_vis_csvfile
        */

	curr_statp->time[IRQ_TIME] = prev_statp->time[IRQ_TIME] = 0;
	for (i = IRQ_BEGIN; i <= IRQ_END; i++) {
		curr_statp->time[IRQ_TIME] += curr_statp->time[i];
		prev_statp->time[IRQ_TIME] += prev_statp->time[i];
	}

        irq_time = curr_statp->time[IRQ_TIME] - prev_statp->time[IRQ_TIME];

        busy_time = (curr_statp->T_sys_time + curr_statp->T_user_time + curr_statp->T_irq_time) -
		(prev_statp->T_sys_time + prev_statp->T_user_time +  prev_statp->T_irq_time);

        total_time = irq_time + (curr_statp->T_idle_time + curr_statp->T_user_time + 
		curr_statp->T_sys_time) - (prev_statp->T_idle_time + 
		prev_statp->T_user_time + prev_statp->T_sys_time);

	ht_total_time = curr_int_serverp->ht_total_time - prev_int_serverp->ht_total_time;
        ht_double_idle = curr_int_serverp->ht_double_idle - prev_int_serverp->ht_double_idle;
        ht_lcpu1_busy = curr_int_serverp->ht_lcpu1_busy - prev_int_serverp->ht_lcpu1_busy;
        ht_lcpu2_busy = curr_int_serverp->ht_lcpu2_busy - prev_int_serverp->ht_lcpu2_busy;
        ht_double_busy = curr_int_serverp->ht_double_busy - prev_int_serverp->ht_double_busy;

	if (server_vis_csvfile) {
		if (total_time) {
                	fprintf(server_vis_csvfile,"%s,%s,%s,%d,%d,%.06f,%.06f,%d,%4.2f,%4.2f,%4.2f,%4.2f,%4.2f,%4.2f,%4.2f,%4.2f,%4.2f,%4.2f",
                        	globals->hostname,
				timestamp,
                        	globals->subdir,
                        	globals->server_id,
                        	vint,
                        	SECS(interval_start - start_time),
                        	SECS(interval_end - start_time),
				globals->nlcpu,
                        	(busy_time * 100.0) / total_time,
                        	((curr_statp->T_sys_time - prev_statp->T_sys_time) * 100.0) / total_time,
                        	((curr_statp->T_user_time - prev_statp->T_user_time) * 100.0) / total_time,
                        	((curr_statp->T_idle_time - prev_statp->T_idle_time) * 100.0) / total_time,
                        	((curr_statp->T_hardirq_sys_time - prev_statp->T_hardirq_sys_time) * 100.0) / total_time,
                        	((curr_statp->T_hardirq_user_time - prev_statp->T_hardirq_user_time) * 100.0) / total_time,
                        	((curr_statp->T_hardirq_idle_time - prev_statp->T_hardirq_idle_time) * 100.0) / total_time,
                        	((curr_statp->T_softirq_sys_time - prev_statp->T_softirq_sys_time) * 100.0) / total_time,
                        	((curr_statp->T_softirq_user_time - prev_statp->T_softirq_user_time) * 100.0) / total_time,
                        	((curr_statp->T_softirq_idle_time - prev_statp->T_softirq_idle_time) * 100.0) / total_time);
		} else {
			fprintf(server_vis_csvfile,"%s,%s,%s,%d,%d,%.06f,%.06f,%d,%4.2f,%4.2f,%4.2f,%4.2f,%4.2f,%4.2f,%4.2f,%4.2f,%4.2f,%4.2f",
                                globals->hostname,
				timestamp,
                                globals->subdir,
                                globals->server_id,
                                vint,
                                SECS(interval_start - start_time),
                                SECS(interval_end - start_time),
				globals->nlcpu,
				0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0);
		}

		if (ht_total_time) {
                	fprintf(server_vis_csvfile,",%4.2f,%4.2f,%4.2f,%4.2f",
                        	(ht_double_idle * 100.0) / ht_total_time,
                        	(ht_lcpu1_busy * 100.0) / ht_total_time,
                        	(ht_lcpu2_busy * 100.0) / ht_total_time,
                        	(ht_double_busy * 100.0) / ht_total_time);
		} else {
			fprintf(server_vis_csvfile,",%4.2f,%4.2f,%4.2f,%4.2f",0.0,0.0,0.0,0.0);
		}

		if (curr_statp->C_switch_cnt - prev_statp->C_switch_cnt) {
                    fprintf(server_vis_csvfile,",%d,%4.2f,%4.2f",
                        (curr_statp->C_switch_cnt - prev_statp->C_switch_cnt),
                        ((curr_statp->C_sleep_cnt - prev_statp->C_sleep_cnt) * 100.0) / (curr_statp->C_switch_cnt - prev_statp->C_switch_cnt),
                        ((curr_statp->C_preempt_cnt - prev_statp->C_preempt_cnt) * 100.0) / (curr_statp->C_switch_cnt - prev_statp->C_switch_cnt));
		    }
		else {
		    fprintf(server_vis_csvfile,",%d,%4.2f,%4.2f",0,0.0,0.0);
		}

                fprintf(server_vis_csvfile,",%3.1f,%lld,%lld,%d,%d,%d,%d",
                        ((curr_rqinfop->total_time - prev_rqinfop->total_time) * 1.0) /
                        ((curr_rqinfop->cnt - prev_rqinfop->cnt) ? (curr_rqinfop->cnt - prev_rqinfop->cnt) : 1),
                        curr_rqinfop->max_time_int,
                        curr_rqinfop->total_time - prev_rqinfop->total_time,
                        curr_rqinfop->cnt - prev_rqinfop->cnt,
                        curr_rqinfop->migrations - prev_rqinfop->migrations,
                        curr_rqinfop->ldom_migrations_in - prev_rqinfop->ldom_migrations_in,
                        curr_rqinfop->ldom_migrations_out - prev_rqinfop->ldom_migrations_out);

                for (i=0; i<NCSTATES; i++) {
                        cstate_total_time += (curr_powerp->cstate_times[i] - prev_powerp->cstate_times[i]);
                }

		if (cstate_total_time) {
                	fprintf(server_vis_csvfile, ",%d,%3.2f,%3.2f,%3.2f,%3.2f,%d",
                        (curr_powerp->power_start_cnt + curr_powerp->power_end_cnt) - 
			    (prev_powerp->power_start_cnt + prev_powerp->power_end_cnt),
                        ((curr_powerp->cstate_times[0] - prev_powerp->cstate_times[0])*100.0)/cstate_total_time,
                        ((curr_powerp->cstate_times[1] - prev_powerp->cstate_times[1])*100.0)/cstate_total_time,
                        ((curr_powerp->cstate_times[2] - prev_powerp->cstate_times[2])*100.0)/cstate_total_time,
                        ((curr_powerp->cstate_times[3] - prev_powerp->cstate_times[3])*100.0)/cstate_total_time,
                        (curr_powerp->power_freq_cnt - prev_powerp->power_freq_cnt));
		} else {
			fprintf(server_vis_csvfile, ",%d,%3.2f,%3.2f,%3.2f,%3.2f,%d",
                        (curr_powerp->power_start_cnt + curr_powerp->power_end_cnt) -
                            (prev_powerp->power_start_cnt + prev_powerp->power_end_cnt),0,0,0,0,
			(curr_powerp->power_freq_cnt - prev_powerp->power_freq_cnt));
		}
                i = IOTOT;
                while (i >= 0) {
                        curr_iostatsp = &curr_int_serverp->iostats[i];
                        prev_iostatsp = &prev_int_serverp->iostats[i];
                        fprintf(server_vis_csvfile, ",%2.0f,%2.0f,%d,%3.1f,%5.3f,%5.3f",
                                ((curr_iostatsp->compl_cnt - prev_iostatsp->compl_cnt) / (vint / 1000.0)),
                                (((curr_iostatsp->sect_xfrd - prev_iostatsp->sect_xfrd)/2048)/ (vint / 1000.0)),
                                ((curr_iostatsp->sect_xfrd - prev_iostatsp->sect_xfrd)/2)/MAX((curr_iostatsp->compl_cnt -
                                        prev_iostatsp->compl_cnt),1),
                                ((curr_iostatsp->cum_async_inflight + curr_iostatsp->cum_sync_inflight) -
                                        (prev_iostatsp->cum_async_inflight + prev_iostatsp->cum_sync_inflight)) /
                                        (MAX((curr_iostatsp->compl_cnt - prev_iostatsp->compl_cnt),1) * 1.0),
                                ((curr_iostatsp->cum_iowait - prev_iostatsp->cum_iowait) /MAX((curr_iostatsp->compl_cnt -
                                        prev_iostatsp->compl_cnt),1) / 1000000.0),
                                ((curr_iostatsp->compl_cnt - prev_iostatsp->compl_cnt) ? (((curr_iostatsp->cum_ioserv -
                                        prev_iostatsp->cum_ioserv) /(curr_iostatsp->compl_cnt - prev_iostatsp->compl_cnt)) /
                                        1000000.0) : 0));
                        i--;
                }

                curr_iostatsp = &curr_int_serverp->iostats[IOTOT];
                prev_iostatsp = &prev_int_serverp->iostats[IOTOT];
                fprintf(server_vis_csvfile, ",%7.0f,%7.0f",
                        (curr_iostatsp->requeue_cnt - prev_iostatsp->requeue_cnt) / (vint / 1000.0),
                        (curr_iostatsp->barrier_cnt - prev_iostatsp->barrier_cnt) / (vint / 1000.0));

		fprintf(server_vis_csvfile, ",%8d,%9.1f,%11.1f,%9.1f,%11.1f",
			curr_int_serverp->netstats.syscall_cnt - prev_int_serverp->netstats.syscall_cnt,
			(curr_int_serverp->netstats.rd_cnt - prev_int_serverp->netstats.rd_cnt) / (vint / 1000.0),
			((curr_int_serverp->netstats.rd_bytes - prev_int_serverp->netstats.rd_bytes)/1024) / (vint / 1000.0),
			(curr_int_serverp->netstats.wr_cnt - prev_int_serverp->netstats.wr_cnt) / (vint / 1000.0),
                        ((curr_int_serverp->netstats.wr_bytes - prev_int_serverp->netstats.wr_bytes)/1024) / (vint / 1000.0));

                fprintf(server_vis_csvfile, ",%d,%d,%d,%d",
                        curr_int_serverp->total_events - prev_int_serverp->total_events,
                        curr_int_serverp->total_buffers - prev_int_serverp->total_buffers,
                        curr_int_serverp->missed_events - prev_int_serverp->missed_events,
                        curr_int_serverp->missed_buffers - prev_int_serverp->missed_buffers);

                fprintf(server_vis_csvfile, "\n");
        }
}



