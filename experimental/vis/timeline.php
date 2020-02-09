<!DOCTYPE html>
<html>
<body>

<?php 

	// The echo comments below only appear if the redirect at the bottom fails ...so they are a debug out as well.

	// truncate the timestamps down to 1e-6
	$start = number_format($_GET['start'],6);
	$end   = number_format($_GET['end'],6);

	echo "Running for time sub-range  Start - " . $start . " End - " . $end . "<br>";

        $path = htmlentities($_GET['path']);
        if (preg_match("/[\>\<,;'|\$()\[\]]/", $path)) {
                exit ("Invalid directory path $path <br>");
        }
	echo "Reports will be placed in " . $path . "/tl_temp  directory <br>";

	// We coerce the path variables we need, the tag timestamp, the temp dir name, etc.

	$tag = htmlentities($_GET['timestamp']);	
        if ((strlen($tag) != 9) || !(preg_match("/^[0-9][0-9][0-9][0-9]+\_[0-9][0-9][0-9][0-9]+/", $tag))) {
                exit ("Invalid Timestamp $tag <br>");
        }

	if ( !chdir( $path ) ) 
		exit("Could not cd to source data dir.  Check the path in the .csv file. <br>");
	
	if ( $_GET['cleanup'] )
		shell_exec( "rm -Rf tl_temp/*"); 

	if ( !mkdir("tl_temp") ) {
		echo "Could not create the tl_temp dir in CWD, it may already exist, or check dir permissions. <br>";
	}



 	if ( !mkdir ("tl_temp/$start-$end") )
		echo "Could not create time subrange dir. It may already exist, or check dir permissions. <br>";



	// Building the tl_temp dir and appending it to the pathname passed in


	echo "Path passed in is: " .  $path  . "<br>";
	$tl_datadir = "tl_temp/$start-$end";
	echo "TL data dir is:  $tl_datadir <br>";
	$fullpath = $path . '/' . $tl_datadir;
	echo "relative path for temp data is : $fullpath <br>";
	echo "Timestamp used is $tag <br>";

	// Now we exec the various reports requested.  Template html files are dropped in the
	// directory with each nodes set of KI data.  The temp tl_temp subdirs use symlinks to
	// get to these template html files.

	// The ascii ki.$tag report is needed for many different vis charts...let's just generate it once

	shell_exec ( "cp /opt/linuxki/experimental/vis/timeline* " . $path);
	shell_exec ( "cp /opt/linuxki/experimental/vis/*.sh " . $path);
	shell_exec ( "/opt/linuxki/kiinfo -kitrace -ts " . $tag . " -starttime " . $start . " -endtime " . $end . " > " . $tl_datadir  . "/ki." . $tag . " 2>&1");
        shell_exec ( "cd " . $tl_datadir . "; ln -s /opt/linuxki/experimental/D3 D3");
	
	if ( $_GET['kparse'] ) { 
			shell_exec ( "mv PIDS PIDS.full; mv VIS VIS.full");
			shell_exec ( "/opt/linuxki/kiinfo -kparse kptree,vis -html -ts " . $tag . " -starttime " . $start . " -endtime " . $end . " > " . $tl_datadir  . "/kp." . $tag . ".html 2>&1");
			shell_exec ( "/opt/linuxki/kiinfo -kipid rqhist,scdetail,npid=10,pidtree,vis,vpct=1.0,vdepth=3 -html -ts " . $tag . " -starttime " . $start . " -endtime " . $end . " > " . $tl_datadir  . "/kipid." . $tag . ".html 2>&1");
			shell_exec ( "cd " . $tl_datadir . "; mv ../../PIDS PIDS; mv ../../VIS VIS; mv ../../PIDS.full ../../PIDS; mv ../../VIS.full ../../VIS"); 
			shell_exec ( "cd " . $tl_datadir . "; ln -s /opt/linuxki/experimental/vis/pid_detail.html pid_detail.html");
			shell_exec ( "cd " . $tl_datadir . "; ln -s /opt/linuxki/experimental/vis/pid_wtree.html pid_wtree.html");
	}

	if ( $_GET['kipid']  && !$_GET['kparse'] ) {
		shell_exec ( "mv PIDS PIDS.full; mv VIS VIS.full");
		shell_exec ( "/opt/linuxki/kiinfo -kipid scdetail,npid=10,pidtree,vis,vpct=1.0,vdepth=3,rqhist -ts " . $tag . " -starttime " . $start . " -endtime " . $end . " > " . $tl_datadir  . "/kipid." . $tag . ".txt 2>&1");
		shell_exec ( "cd " . $tl_datadir . "; mv ../../PIDS PIDS; mv ../../VIS VIS; mv ../../PIDS.full ../../PIDS; mv ../../VIS.full ../../VIS");
	}

	if ( $_GET['kidsk'] ) {
		shell_exec ( "/opt/linuxki/kiinfo -kidsk percpu,npid=20 -ts " . $tag . " -starttime " . $start . " -endtime " . $end . " > " . $tl_datadir  . "/kidsk." . $tag . ".txt 2>&1");
		shell_exec ( "cd " . $tl_datadir . "; ../../kidsk_2_csv.sh " . $tag . " ; ln -s /opt/linuxki/experimental/vis/kidsk_scatter.html  kidsk_scatter.html ");
		shell_exec ( "cd " . $tl_datadir . ";ln -s /opt/linuxki/experimental/vis/kidsk_trace_view.php kidsk_trace_view.php");
		shell_exec ( "cd " . $tl_datadir . ";ln -s /opt/linuxki/experimental/vis/kitrc_extract.sh kitrc_extract.sh");
	}

        if ( $_GET['kirunq'] ) {
                shell_exec ( "/opt/linuxki/kiinfo -kirunq -ts " . $tag . " -starttime " . $start . " -endtime " . $end . " > " . $tl_datadir  . "/kirunq." . $tag . ".txt  2>&1");
        }

	if ( $_GET['kifutex'] ) {
		shell_exec ( "/opt/linuxki/kiinfo -kifutex -ts " . $tag . " -starttime " . $start . " -endtime " . $end . " > " . $tl_datadir  . "/kifutex." . $tag . ".html 2>&1");
		shell_exec ( "cd " . $tl_datadir . "; ../../futex_2_csv.sh " . $tag . " ; ln -s /opt/linuxki/experimental/vis/futex_scatter.html  futex_scatter.html  ");
	}

	if ( $_GET['kitrace'] ) {
//		shell_exec ( "/opt/linuxki/kiinfo -kitrace  -ts " . $tag . " -starttime " . $start . " -endtime " . $end . " > " . $tl_datadir  . "/ki." . $tag . " 2>&1");
	}

   	header("Location: $fullpath"); /* Redirect browser */
	exit();

?>

</body>
</html>
