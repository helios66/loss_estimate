<?php

define(CURRENT_VERSION, "1.00");

/*
 * Makes all GET and POST variables also global variables.
 * If called within a function, global variables must be then
 * made locally available with "global $variable".
 */
function set_vars() {
	foreach($_GET as $key => $value)
		$GLOBALS[$key]=$value;

	foreach($_POST as $key => $value)
		$GLOBALS[$key]=$value;
} /* set_vars() */

function rand_string($len, $chars = 'abcdefghijklmnopqrstuvwxyz0123456789')
{
   $string = '';
   for ($i = 0; $i < $len; $i++)
   {
       $pos = rand(0, strlen($chars)-1);
       $string .= $chars{$pos};
   }
   return $string;
} /* rand_string() */

?>


