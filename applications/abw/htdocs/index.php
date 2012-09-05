<?php

require_once("conf.php"); 
require_once("common.php"); 

/*
 * Predefined time intervals and granularities
 *
 * Keep in mind the following requirements:
 *
 *   - each resolution must be >= time of one pixel on X axis
 *     (set in rrd_graph_all.sh) otherwise time of one pixel is used
 *
 *   - UNIX timestamps of both start time and end time must be multiples
 *     of both resolutions (set time_length accordingly and compute
 *     end time to be on boundary) and it is safer to skip the most recent
 *     samples, see variable $hhmmYYYYMMDD below
 *
 *   - RRD files must include RRA samples for the whole requested period,
 *     create RRD files to include enough RRA samples for possible browsing
 *     in time axis
 */

$time_description[0]="last 10 mins (interval 1 sec, avg/max 30 sec)";
$time_description[1]="last 1 hour (interval 10 sec, avg/max 3 min)";
$time_description[2]="last 10 hours (interval 1 min, avg/max 20 min)";
$time_description[3]="last 1 day (interval 3 min, avg/max 1 hour)";
$time_description[4]="last 1 week (interval 20 min, avg/max 6 hour)";
$time_description[5]="last 1 month (interval 3 hour, avg/max 1 day)";
$time_description[6]="last 1 year (interval 1 day, avg/max 1 month)";

$r1[0]=1;
$r2[0]=30;
$time_length[0]="10min";

$r1[1]=10;
$r2[1]=180;
$time_length[1]="1h";

$r1[2]=60;
$r2[2]=1200;
$time_length[2]="10h";

$r1[3]=180;
$r2[3]=3600;
$time_length[3]="1day";

$r1[4]=120;
$r2[4]=21600;
$time_length[4]="1week";

$r1[5]=10800;
$r2[5]=86400;
$time_length[5]="1month";

$r1[6]=86400;
$r2[6]=2628000;
$time_length[6]="1year";

/*
 * Define graph types
 */

$graph_type_label=array("l4", "apps");
$graph_type_description=array("L3/L4 protocols", "Application protocols");

/*
 * Set global variables (from the web form)
 */
 set_vars();

$current_ts=time();

/*
 * Default values
 */

if (!isset($default)) {
	$graph_types[0]="l4";
	$graph_types[1]="apps";
	$subject_all=1;
	$times[0]=$r1[0] . "_" . $r2[0] . "_" . $time_length[0];
	/* $times[1]=$r1[1] . "_" . $r2[1] . "_" . $time_length[1];
	$times[2]=$r1[2] . "_" . $r2[2] . "_" . $time_length[2]; */

	$time_type="predefined";

	$start_time_minute=date("i", $current_ts-600);
	$start_time_hour=date("H", $current_ts-600);
	$start_time_day=date("j", $current_ts-600);
	$start_time_month=date("n", $current_ts-600);
	$start_time_year=date("Y", $current_ts-600);

	$end_time_minute=date("i", $current_ts);
	$end_time_hour=date("H", $current_ts);
	$end_time_day=date("j", $current_ts);
	$end_time_month=date("n", $current_ts);
	$end_time_year=date("Y", $current_ts);

	$r1_number=1;
	$r1_unit="seconds";
	$r2_number="30";
	$r2_unit="seconds";

	$maxline="a";
}

/* 
 * For conversion of month number to month name 
 */

$monthNumberToLongName=array("January", "February", "March", "April", "May", 
	"June", "July", "August", "September", "October", "November", "December");

function time_to_sec($number, $unit) {
	switch ($unit) {
		case "seconds":
			return $number;
		case "minutes":
			return $number * 60;
		case "hours":
			return $number * 3600;
		case "days":
			return $number * 86400;
		case "weeks":
			return $number * 86400 * 7;
		case "months":
			return $number * 2628000; /* for non-leap years */
		case "years":
			return $number * 86400 * 365; /* for non-leap years */
		default:
			return -1;
	}
} /* time_to_sec() */

function time_diff($time1, $time2) {
	if ($time2["sec"] > $time1["sec"]) {

		if ($time2["sec"] > ($time1["sec"]+1))
			$res=$time2["sec"] - $time1["sec"];
		else
			$res=0;

		$res=$res+(float)(1000000-$time1["usec"])/1000000 +
					 (float)($time2["usec"])/1000000;
	}
	else
		$res=(float)($time2["usec"]-$time1["usec"])/1000000;

	return $res;
} /* time_diff() */

/*
 * Start application
 */

$func="main()";

openlog($_SERVER['REMOTE_USER'], LOG_PID, LOG_LOCAL0);
syslog(LOG_INFO, "$func: starting");

echo "<html>\n";
echo "<head>\n";
echo "<link rel=\"StyleSheet\" type=\"text/css\" href=\"style.css\">\n";
echo "</head>\n";
echo "<body>\n";

if (defined('NET_IMG'))
	echo "<img id=\"logo\" src=\"" . NET_IMG . "\" align=\"right\" width=\"200\">\n";

echo "<h2>ABW - Passive capacity usage monitoring</h2>\n";

if (!isset($subject_selected))
	$subject_selected=1;

echo "<form method=get action=\"index.php\">\n";

/*
 * Print form to select graph types
 */

/* if (!isset($graph_types))
	$graph_types[0]="l4"; */

echo "<h3>Step 1: Select type of graphs:</h3><p>\n";
echo "<table border=1><tr>\n";
foreach ($graph_type_label as $key => $value) {
	echo "<td>$graph_type_description[$key]</td>";
	echo "<td><input type=checkbox name=\"graph_types[]\" value=\"$value\"";
	if (isset($graph_types)) {
		if (in_array($value, $graph_types))
			echo " checked";
	}
	echo "></td>\n";
}
echo "</tr></table>\n";

/*
 * Print form to select monitored links
 */

/* if (!isset($subjects))
	$subjects[0]="Prague_PoP"; */

$half=count($subject_label)/2 + $subject_label%2;
$i=0;

echo "<p>\n";
echo "<h3>Step 2: Select monitored links:</h3><p>\n";
echo "<table border=1>\n";
foreach ($subject_label as $key => $value) {
	/* if (($i%2)==0) */
		echo "<tr>\n";
	echo "<td>$subject_description[$key]</td>";
	echo "<td><input type=checkbox name=\"subjects[]\" value=\"$value\"";
	if (isset($subjects)) {
		if (in_array($value, $subjects))
			echo " checked";
	}
	if ($subject_disabled[$key] > 0)
		echo " disabled";
	echo "></td>\n";
	/* if (($i%2)>0) */
		echo "</tr>\n";
	$i++;
}

/* if (($i%2)==0)
	echo "<tr>\n"; */
echo "<tr><td>all links</td>\n";
echo "<td><input type=checkbox name=\"subject_all\"";
if (isset($subject_all))
   echo " checked";
echo "></td></tr>\n";
$i++;

/* if (($i%2)>0)
	echo "<td>&nbsp;</td><td>&nbsp;</td>"; */
echo "</table>\n";

/* echo "<p><i>Note: PIONIER monitoring stations are down due to moving to a different subnet.</i>\n"; */

/*
 * Print form to select time period and resolution
 */

echo "<p>\n";
echo "<h3>Step 3: Select time period and resolution:</h3>\n";
echo "(<a href=\"aggregation.html\">How is data aggregated?</a>)\n";
echo "<p>\n"; 

echo "Time type:<br>\n";
echo "<table><tr><td>Predefined <input type=radio name=\"time_type\" value=\"predefined\"";
if (!strcmp($time_type, "predefined"))
	echo " checked";
echo "></td><td width=20>&nbsp;</td>";
echo "<td>User defined <input type=radio name=\"time_type\" value=\"user_defined\"";
if (!strcmp($time_type, "user_defined"))
   echo " checked";
echo "></td><td width=20>&nbsp;</td>";
echo "</tr></table>";

echo "<p>\n";

echo "<table>\n";
echo "<tr><td>Predefined:</td><td width=20>&nbsp;</td><td>User defined:</td></tr>\n";

echo "<tr><td><table border=1>\n";
foreach ($time_description as $key => $value) {
	echo "<tr>\n";
	echo "<td>$value</td>\n";
	$time_label=$r1[$key] . "_" . $r2[$key] . "_" . $time_length[$key];
   echo "<td><input type=checkbox name=\"times[]\" value=\"" . $time_label . "\"";
	if (isset($times)) {
		if (in_array($time_label, $times))
   		echo " checked";
	}
	echo "></td>\n";
	echo "</tr>\n";
}
echo "<tr>\n";
echo "<td>all predefined time periods</td>\n";
echo "<td><input type=checkbox name=\"time_all\"";
if (isset($time_all))
	echo " checked";
echo "></td>\n";
echo "</tr>\n";
echo "</table>\n";

echo "</td><td>&nbsp;</td><td>\n";

echo "<table><tr><td>Start time:</td><td width=\"20px\">&nbsp;</td><td>Start date:</td></tr>\n";

echo "<tr><td><select name=start_time_hour>";
	for ($i=0; $i<=23; $i++) {
		echo "<option value=$i";
		if ($start_time_hour==$i)
			echo " selected";
		echo ">";
		printf("%02d", $i);
		echo "</option>\n";
	}
echo "</select>\n";

echo "<select name=start_time_minute>";
	for ($i=0; $i<=59; $i++) {
		echo "<option value=$i";
		if ($start_time_minute==$i)
			echo " selected";
		echo ">";
		printf("%02d", $i);
		echo "</option>\n";
	}
echo "</select></td><td width=\"20px\">&nbsp;</td>\n";

echo "<td><select name=start_time_day>";
	for ($i=1; $i<=31; $i++) {
		echo "<option value=$i";
		if ($start_time_day==$i)
			echo " selected";
		echo ">$i</option>\n";
	}
echo "</select>\n";

echo "<select name=start_time_month>";
	for ($i=1; $i<=12; $i++) {
		echo "<option value=$i";
		if ($start_time_month==$i)
			echo " selected";
		echo ">" . $monthNumberToLongName[$i-1] . "</option>\n";
	}
echo "</select>\n";

echo "<select name=start_time_year>";
	for ($i=2006; $i<=2015; $i++) {
		echo "<option value=$i";
		if ($start_time_year==$i)
			echo " selected";
		echo ">$i</option>\n";
	}
echo "</select></td></tr></table>\n";

echo "<table><tr><td>End time:</td><td width=\"20px\">&nbsp;</td><td>End date:</td></tr>\n";

echo "<tr><td><select name=end_time_hour>";
	for ($i=0; $i<=23; $i++) {
		echo "<option value=$i";
		if ($end_time_hour==$i)
			echo " selected";
		echo ">";
		printf("%02d", $i);
		echo "</option>\n";
	}
echo "</select>\n";

echo "<select name=end_time_minute>";
	for ($i=0; $i<=59; $i++) {
		echo "<option value=$i";
		if ($end_time_minute==$i)
			echo " selected";
		echo ">";
		printf("%02d", $i);
		echo "</option>\n";
	}
echo "</select></td><td width=\"20px\">&nbsp;</td>\n";

echo "<td><select name=end_time_day>";
	for ($i=1; $i<=31; $i++) {
		echo "<option value=$i";
		if ($end_time_day==$i)
			echo " selected";
		echo ">$i</option>\n";
	}
echo "</select>\n";

echo "<select name=end_time_month>";
	for ($i=1; $i<=12; $i++) {
		echo "<option value=$i";
		if ($end_time_month==$i)
			echo " selected";
		echo ">" . $monthNumberToLongName[$i-1] . "</option>\n";
	}
echo "</select>\n";

echo "<select name=end_time_year>";
	for ($i=2006; $i<=2015; $i++) {
		echo "<option value=$i";
		if ($end_time_year==$i)
			echo " selected";
		echo ">$i</option>\n";
	}
echo "</select></td></tr></table>\n";


/* Interval + avg/max are as a separate table */
echo "<p><table><tr><td>Resolution:</td><td>Avg/Max:</td></tr><tr>\n";
echo "<td><input type=text size=3 name=r1_number value=\"$r1_number\"></input>\n";
echo "<select name=r1_unit>";
$r1_units=array("seconds", "minutes", "hours", "days", "weeks", "months",
   "years");
foreach ($r1_units as $value) {
	echo "<option value=$value";
	if ($r1_unit==$value)
		echo " selected";
	echo ">$value</option>\n";
}
echo "</select></td>\n";
echo "<td><input type=text size=3 name=r2_number value=\"$r2_number\"></input>\n";
echo "<select name=r2_unit>";
$r2_units=array("seconds", "minutes", "hours", "days", "weeks", "months",
   "years");
foreach ($r2_units as $value) {
	echo "<option value=$value";
	if ($r2_unit==$value)
		echo " selected";
	echo ">$value</option>\n";
}
echo "</select></td>\n";
echo "</tr></table>\n";


echo "</td>\n";

echo "</tr></table>\n";

echo "<p><h3>Step 4: Choose options:</h3>";

echo "<p>Draw maximum line: (<a href=\"max_line.html\">What does it mean?</a>)<br>\n";
echo "<table><tr><td>Yes <input type=radio name=\"maxline\" value=\"y\"";
if (!strcmp($maxline, "y"))
	echo " checked";
echo "></td><td width=20>&nbsp;</td>";
echo "<td>No <input type=radio name=\"maxline\" value=\"n\"";
if (!strcmp($maxline, "n"))
   echo " checked";
echo "></td><td width=20>&nbsp;</td>";
echo "<td>Auto <input type=radio name=\"maxline\" value=\"a\"";
if (!strcmp($maxline, "a"))
   echo " checked";
echo "> (for Avg/Max > 30 min)</td></tr></table>";

/* echo "<p>Note: selecting all time periods will require a lot of processing time\n"; */

echo "<p>\n";
echo "<input type=submit name=button_name value=\"Generate graphs\">\n";
echo "<input type=hidden name=action value=\"gen_graph\">\n";
echo "<input type=hidden name=default value=\"0\">\n";
echo "(at least one option must be selected in each step 1 - 3 to produce graphs)";
/* when all options are selected, generation of graphs can take a long time */

echo "</form><br>\n";

if ($action=="gen_graph") {

	$session=rand_string(6);

	/* foreach (glob($GRAPH_DIR . "/*") as $filename)
      unlink($filename); */

	/* If at least one graph type, one subject and one time period were
		selected, then generate and show graphs */

	if (isset($graph_types) && 
		 (isset($subjects) || isset($subject_all)) && 
		 (isset($times) || isset($time_all) || strcmp($time_type, "predefined"))) {

		$total_time=0;
		echo "<p>\n";
		/* echo "<table border=\"1\">\n";
		echo "<tr><td>Graph type</td><td>Link</td><td>Time (gen / copy)</td></tr>\n"; */

		mkdir($GRAPH_DIR . "/" . $session);

		/* Go over all selected graph types */

		foreach($graph_type_label as $graph_type_key => $graph_type_value) {
			if (in_array($graph_type_value, $graph_types)) {

				/* Go over all subjects and for each selected subject issue
					one remote command to generate graphs */

				$i=0;
				foreach ($subject_label as $subject_key => $subject_value) {
		      	if ((isset($subject_all) || in_array($subject_value, $subjects)) &&
						 !$subject_disabled[$subject_key]) {

						$hostname=$subject_hostname[$i];

						$command="ssh " . $REMOTE_USERNAME . "@" . $subject_hostname[$i] . " \"" . $GRAPH_SCRIPT . " --session=" . $session . " --graph_type=" . $graph_type_value . " --label=" . $subject_value . " --parameters_id=1";

						/* If maxline is not default ("a"), then request it */

						if ($maxline!="a")
							$command=$command . " --maxline=" . $maxline;

						/* Append one --time argument for each selected time period */

						if (!strcmp($time_type, "predefined")) {
					
							foreach ($time_description as $time_key => $time_value) {
								$time_label=$r1[$time_key] . "_" . $r2[$time_key] . 
									"_" . $time_length[$time_key];
					   		if (isset($time_all) || in_array($time_label, $times)) {
									/* Rounding was removed */
									$hhmmYYYYMMDD=date("G:i Ymd", (int)(time() ));
									// $hhmmYYYYMMDD=date("G:i Ymd", (int)(time() / $r2[$time_key]) * $r2[$time_key]);

							 		$command=$command . " --time=\\\"" .
							 			$r1[$time_key] . " " . $r2[$time_key] . " " .
										$time_length[$time_key] . " " . $hhmmYYYYMMDD . "\\\"";
								}
							}
						} /* if (!strcmp($time_type, "predefined")) */
						else {

							$r1_sec=time_to_sec($r1_number, $r1_unit);
							$r2_sec=time_to_sec($r2_number, $r2_unit);
							if ($r1_sec<=0) {
								$r1_sec=1; $r1_number=1; $r1_unit="seconds";
							 	echo "<span class=\"warning\">Warning: resolution must be greater than zero (resolution was adjusted to 1 second).</span><br>\n";
							}
							if ($r2_sec<=0) {
								$r2_sec=30; $r2_number=30; $r2_unit="seconds";
							 	echo "<span class=\"warning\">Warning: avg/max must be greater than zero (avg/max was adjusted to 30 seconds).</span><br>\n";
							}
							if ($r2_sec<$r1_sec) {
								$r2_sec=$r1_sec; $r2_number=$r1_number; $r2_unit=$r1_unit;
							 	echo "<span class=\"warning\">Warning: avg/max must be greater than or equal to resolution (avg/max was adjusted to equal resolution).</span><br>\n";
							}

							/* Compute timestamps of start and end of requested period */

							$start_timestamp=mktime($start_time_hour, $start_time_minute, 0, $start_time_month, $start_time_day, $start_time_year);

							$end_timestamp=mktime($end_time_hour, $end_time_minute, 0, $end_time_month, $end_time_day, $end_time_year);

							if ($end_timestamp > $current_ts) {
								$end_timestamp=$current_ts;
								$end_timestamp=(int)($end_timestamp / 60);
								$end_timestamp=$end_timestamp * 60;
								$end_time_minute=date("i", $end_timestamp);
                        $end_time_hour=date("H", $end_timestamp);
                        $end_time_day=date("j", $end_timestamp);
                        $end_time_month=date("n", $end_timestamp);
                        $end_time_year=date("Y", $end_timestamp);
								echo "<span class=\"warning\">Warning: end time must not be in future (end time was adjusted to current time).</span><br>\n";
							}

							if ($end_timestamp <= $start_timestamp) {
								$start_timestamp=$end_timestamp-600;
								$start_time_minute=date("i", $start_timestamp);
								$start_time_hour=date("H", $start_timestamp);
								$start_time_day=date("j", $start_timestamp);
								$start_time_month=date("n", $start_timestamp);
								$start_time_year=date("Y", $start_timestamp);
								echo "<span class=\"warning\">Warning: end time must be later than start time (start time was adjusted to end time - 10 minutes).</span><br>\n";
							}

							$time_length_number=$end_timestamp - $start_timestamp;
							/* echo "time_length_number: $time_length_number ($end_timestamp - $start_timestamp)<br>\n"; */
							$time_length_unit="seconds";

							$hhmmYYYYMMDD=date("G:i Ymd", $end_timestamp);

							$command=$command . " --time=\\\"" . $r1_sec . " " . 
								$r2_sec . " " . $time_length_number . 
								$time_length_unit . " " . $hhmmYYYYMMDD . "\\\"";
									
						}
		
						/* Execute command and measure how long it takes */

						$command=$command . " 2>&1 > /dev/null\"";
						syslog(LOG_DEBUG, "Command: $command");
						$time1=gettimeofday();
						system($command);
						$time2=gettimeofday();
						$diff=time_diff($time1, $time2);
						$total_time+=$diff;

						$command="scp " . $REMOTE_USERNAME . "@" . $subject_hostname[$i] . ":" . $REMOTE_GRAPH_DIR . "/" . $session . "/* " . $GRAPH_DIR . "/" . $session;	
						syslog(LOG_DEBUG, "Command: $command");
						$time1=gettimeofday(TRUE);
						system($command);
						$time2=gettimeofday(TRUE);
						$diff=time_diff($time1, $time2);
						$total_time+=$diff;
					}
				$i++;
				}
			} /* if (in_array($graph_type_value, $graph_types)) */
		} /* foreach($graph_type_label as $graph_type_key => $graph_type_value) */
		/* printf("<tr><td>Total time</td><td>&nbsp;</td><td>%.02fs</td></tr>\n", $total_time);
		echo "</table>\n"; */

		echo "<p>\n<table>\n";
		$graphs=0;

		foreach ($subject_label as $subject_key => $subject_value) {
	      if ((isset($subject_all) || in_array($subject_value, $subjects)) &&
				 !$subject_disabled[$subject_key]) {

				if (!strcmp($time_type, "predefined")) {
					
					foreach ($time_description as $time_key => $time_value) {
						$time_label=$r1[$time_key] . "_" . $r2[$time_key] . "_" . 
							$time_length[$time_key];
				   	if (isset($time_all) || in_array($time_label, $times)) {
							foreach($graph_types as $graph_type) {

								$graph_filename="graph/" . $session . "/graph_" . $subject_value . "_" . 
									$graph_type . "_" . $r1[$time_key] . "s_" .
									$r2[$time_key] . "s_" . $time_length[$time_key] . 
									".png";

								if (($graphs%2)==0)
									echo "<tr>\n";
	
								echo "<td width=430 align=center>\n";
								echo "  <table>\n";
								echo "  <tr>\n";
								echo "    <td align=center width=450><a href=\"$graph_filename\"><img width=400 src=\"$graph_filename\"></a></td>\n";
								echo "  </tr>\n";
								echo "  <tr>\n";
								echo "    <td align=center width=450>" . $graph_type_description[array_search($graph_type, $graph_type_label)] . ", Monitored link: " . $subject_description[$subject_key] . "<br>$time_description[$time_key]</td>\n";
								echo "  </tr>\n";
								echo "  </table>\n";
								echo "</td>\n";

								if (($graphs%2)!=0)
									echo "</tr>\n";
		
								$graphs++;

							} /* foreach ($graph_types as $graph_type) */
						}
					} 

				} /* if (!strcmp($time_type, "predefined")) */
				else {
					foreach($graph_types as $graph_type) {
						$graph_filename="graph/" . $session . "/graph_" . $subject_value . "_" .
							$graph_type . "_" . $r1_sec . "s_" . $r2_sec . "s_" .
							$time_length_number . $time_length_unit . ".png";

						if (($graphs%2)==0)
							echo "<tr>\n";

						echo "<td width=430 align=center>\n";
						echo "  <table>\n";
						echo "  <tr>\n";
						echo "    <td align=center width=450><a href=\"$graph_filename\"><img width=400 src=\"$graph_filename\"></a></td>\n";
						echo "  </tr>\n";
						echo "  <tr>\n";
						echo "    <td align=center width=450>" . $graph_type_description[array_search($graph_type, $graph_type_label)] . ", Monitored link: " . $subject_description[$subject_key] . "<br>\n";
						printf("From %d:%02d %d.%02d.%d to %d:%02d %d.%02d.%d<br>\n", 
							$start_time_hour, $start_time_minute, $start_time_day, 
							$start_time_month, $start_time_year, $end_time_hour,
							$end_time_minute, $end_time_day, $end_time_month,
							$end_time_year);
						echo "(interval $r1_number $r1_unit, Avg/Max $r2_number $r2_unit)</td>\n";
						echo "  </tr>\n";
						echo "  </table>\n";
						echo "</td>\n";

						if (($graphs%2)!=0)
							echo "</tr>\n";
			
						$graphs++;
					} /* foreach ($graph_types as $graph_type) */
				}

			}
		} /* foreach($subject_label as $subject_key => $subject_value) */

		echo "</table>\n";

	} /* if (isset($graph_types) && ... */

} /* if ($action=="gen_graph") */

echo "</body>\n";
echo "</html>\n";

?>
