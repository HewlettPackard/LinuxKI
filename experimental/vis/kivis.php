<!DOCTYPE html>
<html>
<head>
<style type="text/css">
textarea {
   font-size: 8pt;
   font-family: courier new;
   font-weight: bold;
}
</style>
</head>
<body>
<?php
	// Set up variables

	$type = $_GET['type'];
	$pid = $_GET['pid'];
	$start = $_GET['start'];
	$end = $_GET['end'];
        $io_time = $_GET['iotime'];
	$cwd = shell_exec("pwd");
	$ts = $_GET['ts'];

	// Generate the data to be displayed in the formatted textarea

	switch ($type) {
		case kitrace:
			$header = "<h3>LinuxKI trace records - </h3>";
			$data = shell_exec ("/opt/linuxki/kiinfo -kitrace pid=" . $pid . 
				" -ts " . $ts . " -starttime " . $start . 
				" -endtime " . $end. " 2>&1 ");
			break;
		case kitrace_disk:
			$header = "<h3>LinuxKI I/O trace records - I/O of interest completed at $io_time.<br>Timespan is +- the IO service time, and typically starts with the block_rq_issue record.</h3>";
			$data = shell_exec ("/opt/linuxki/kiinfo -kitrace pid=" . $pid .
                                " -ts " . $ts . " -starttime " . $start .
                                " -endtime " . $end. " 2>&1 ");
			break;
		case kipid:
			$header = "<h3>LinuxKI kipid report - </h3>";
			$data = shell_exec ("/opt/linuxki/kiinfo -kipid rqhist,scdetail,npid=20,pid=" . $pid . 
				" -ts " . $ts . " -starttime " . $start . " -endtime " .  $end);
			break;
		case pid_switch:
			$header = "<h3>LinuxKI scheduling timeline - </h3>";
			shell_exec ("/opt/linuxki/experimental/vis/pid_switch.sh " . $pid . " " . $ts . " " . $start . " " . $end .  " 2>&1");
			// $data = shell_exec ("/opt/linuxki/experimental/vis/pid_switch.sh " . $pid . " " . $ts . " " . $start . " " . $end . );
			header("Location: VIS/" . $pid . "/pid_switch.html"); /* Redirect browser */
			break;
		default:
			$data = "no default, choose a tyep field";
	}
        
	// Define the form window and display $data text content from above

	echo "$header
        <form  target='_blank' action='$_SERVER[php_self]' method='post' >
        <textarea name='kidetail' cols='190' rows='56'> $data </textarea>
        </form>";

        exit(" ");
?>

</body>
</html>
