<?php 
$action = $_POST['action'];

$comm_file = "./comm";
$log_file = "./log.txt";

//check if ear is running
if ($action == "check" || $_GET['action'] == "check") {
	/*if (`pgrep mapid | wc -l` == 0)
		echo "off:The mapi daemon is not running!";
	else */
	$pid = trim(`cat /var/run/ear_monitor.pid`);
	$command = trim(`ps -p $pid -o comm=`);
	if ("$command" == "earmonitor")
		echo "ok:";
	else
		echo "off:The EAR monitor is not running! $pid - $command";
}
//check parameters
else if ($action == "cparams") {
    $handle = fopen("./comm", "w");
    fputs($handle, "{$_POST['str_len']} {$_POST['dest_thres']} {$_POST['time_thres']}\n");
    fclose($handle);
}
//xxx fix
else if ($action == "getlog") {
    $line = $_POST["line"];
    $logs = file_get_contents($log_file);
    $logs = explode("\n", $logs);
    $logs_len = count($logs);
    
    for ($i=$line; ($i < $logs_len) && ($line-$i < 100); $i++) {
		echo $logs[$i] . "\n";
    }
}
?>

