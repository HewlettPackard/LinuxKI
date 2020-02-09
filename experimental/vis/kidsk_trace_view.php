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
        $io_time = number_format($_GET['iotime'],6);
	$start = number_format($_GET['start'],6);
	$end = number_format($_GET['end'],6);
        shell_exec ( "./kitrc_extract.sh " . $start . "  " . $end);
        $filename = "./kitrc.txt";
        $fh = fopen($filename, "r") or die("Could not open file!");
        $data = fread($fh, filesize($filename)) or die("Could not read file!");
        fclose($fh);
        echo "<h3>LinuxKI trace records - I/O of interest completed at $io_time.<br>Timespan is +- the IO service time, and typically starts with the block_rq_issue record.</h3>
        <form  target='_blank' action='$_SERVER[php_self]' method='post' >
        <textarea name='newd' cols='150%' rows='50'> $data </textarea>
        </form>";

        exit(" ");
?>

</body>
</html>
