<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />
<title>Alerts Index</title>

<link rel="stylesheet" href="stylesheet.css" type="text/css">

</head>

<body>
<!-- title -->
<p class="title">Alerts Index</p>

<!-- first table -->
<div align="center">
	<table width="471" class="table">
  <tr>
    <th width="130" scope="col">Alert ID </th>
    <th width="325" scope="col">Alert Date</th>
  </tr>
<?php

    $limit   = 100;
	$bgcolor = "#E0E0E0"; // light gray
	$page    = $_GET['page'];

	if(empty($page)){
		$page = 0;
	}

	$next = $page + 1;
	$prev = $page - 1;
    
    for ($id=$page*$limit; $id < $page*$limit+$limit; $id++) {
		($bgcolor == "#E0E0E0")?$bgcolor="#FFFFFF":$bgcolor = "#E0E0E0";
		if (!file_exists('./alerts/'.$id))
			break;
		echo "<tr bgcolor=\"$bgcolor\">
	    	<td><a href=\"./showAlert.php?id=$id\">$id</a></td>
	    	<td>".date("r", filemtime('./alerts/' . $id))."</td>
	    	</tr>";
	}

	if ($id == 0) {
		echo "<tr bgcolor=\"$bgcolor\">
	    	<td>None yet</td>
	    	<td>None yet</td>
	    	</tr>";
    }
?>
	</table>

	<table class="pagination"><tr>
		<td><?php echo ($prev>=0)?"<a href=\"./alerts.php?page=$prev\"><< previous</a>":"";?></td>
		<td><form action="./showAlert.php">
			<input type="text" name="page" size="3" value=<?php echo $page?>>
			<input type="hidden" value="submit"> </form></td>
		<td><a href="./alerts.php?page=<?php echo $page + 1 ?>">next >></a></td>
	</tr></table>
</div>
</body>
</html>
