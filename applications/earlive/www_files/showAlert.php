<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />
<title>EAR Alert</title>
<link rel="stylesheet" href="stylesheet.css" type="text/css">
</head>
<?php 

	
	//Create a string split function for pre PHP5 versions
	function mystr_split($str, $nr) { 
		//Return an array with 1 less item then the one we have
		return array_slice(split("#",chunk_split($str, $nr, '#')), 0, -1);
	}


	$id = $_GET["id"];
	$error = false;
	
	if (!is_numeric($id)) {
	    echo "<h1 align=\"center\"> Alert id is not a number! </h1>";
	    $error = true;
	}
	else if (!file_exists('./alerts/' . $id)) {
	    echo "<h1 align=\"center\"> Alert not Found! </h1>";
	    $error = true;
	}
	
	if ($error) {
	    $finger = 0x0;
	    $time = 0;
	    $payload[0] = array("00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ", "................");
	    $dests[0] = array("0.0.0.0:0", "0.0.0.0:0", 0, "0.0");
	}
	else {
	    $alert = file_get_contents('./alerts/' .$id);
	    $alarr = explode("\n", $alert);
	    list($finger, $time, $bool) = explode(" ", $alarr[1]);
	    for ($i=2; $alarr[$i] != ""; $i++)
		$payload[] = mystr_split($alarr[$i], 48);
	    while ($alarr[++$i] != "")
		$dests[] = sscanf($alarr[$i], "%s -> %s offset: %d timestamp: %s");
	}
?>

<body>
<div align="center">

<!-- Alert title -->
<table size="700" class="pagination"><tr>
<td width="200" align="left"><a href="./showAlert.php?id=<?php echo $id-1;?>">Prev. Alert</a></td>
<td width="300"><p class="blinked">ALERT #<?php echo $id;?></p></td>
<td width="200" align="right"><a href="./showAlert.php?id=<?php echo $id+1;?>">Next	Alert</a></td>
</tr></table>

<!-- first table -->

<table width="554" class="table">
  <tr>
    <th width="177" scope="row">Substring fingerprint </th>
    <td width="361"><?php echo $finger; ?></td>
  </tr>
  <tr>
    <th scope="row">Alert Timestamp </th>
    <td><?php echo $time; ?></td>
  </tr>
</table>
</div>
<br />

<!-- Second table -->
<div align="center">
  <table width="700" class="table">
    <!--DWLayoutTable-->
    <tr>
      <th width="492" height="23" scope="col">Packet Bytes</th>
      <th width="192" valign="top" scope="col">ASCII</th>
    </tr>
    <?php 
    foreach ($payload as $line)
	echo " <tr>
	    <td class=\"payload\">&nbsp;$line[0]</td>
	    <td class=\"payload\">&nbsp;$line[1]</td>
	    </tr>";
    ?>
  </table>
</div>
<br />
<!-- Third table -->
<div align="center"><table width="700" class="table">
  <tr>
    <th width="160" scope="col">Source</th>
    <th width="160" scope="col">Destination</th>
    <th width="60" scope="col">Offset</th>
    <th width="320" scope="col">Timestamp</th>
  </tr>
  <?php
  foreach ($dests as $elem)
    echo " <tr>
	    <td>$elem[0]</td>
	    <td>$elem[1]</td>
	    <td>$elem[2]</td>
	    <td>$elem[3]</td>
	</tr>";
    ?>
</table>

</div>

</body>
</html>
