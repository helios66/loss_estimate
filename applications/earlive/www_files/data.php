<?php
$time = $_POST['time'];

define('LINE_LEN', 52);

//see if monitor and mapid are still running
$np = `pgrep 'ear_monitor'|wc -l`;
//if ($np != 1) //something went wrong
//	echo "off:";
//else { // mapid and monitor are up and running !
	$handle = fopen('./data', 'r');
	if ($time < 0) //clients is initializing
		fseek($handle, $time*LINE_LEN, SEEK_END);
	else
		fseek($handle, $time*LINE_LEN, SEEK_SET);
	
	while (TRUE) {
		$line = trim(fgets($handle));
		$line = preg_replace("/\ +/", " ", $line);
		if (!feof($handle))
			echo "ok:$line\n";
		else {
			echo "na:";
			break;
		}
	}
	fclose($handle);
//}
?>
