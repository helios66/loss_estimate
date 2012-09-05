<?

/* BEGINNING OF USER CONFIGURATION SECTION */

/* Username used by web server to login to remote monitoring stations */
define(REMOTE_USERNAME, "abw");

/* Directory on remote monitoring stations where ABW is installed */
define(ABW_DIR, "/usr/local/abw");

/* Directory on remote monitoring stations where ABW stores work data */
define(ABW_VAR_DIR, "/var/lib/abw");

/* Directory on the web server where ABW scripts should be installed */
define(WEB_DIR, "/srv/www/abw");

/*
 * Define subjects
 */

/* 
 * Single-word names (without spaces) refering to monitored links.
 * They must be the same as "label" fields in [subject] sections in
 * the abw.conf configuration file.
 */
$subject_label=array(
	"sa3-pm1",
	"sa3-pm2",
	"sa3-pm3",
	"sa3-pm4",
	"sa3-pm5"
);

/*
 * Description of monitored links. Can include spaces. It is probably a good 
 * idea to make them the same as "description" fields in [subject] sections in 
 * the abw.conf configuration file, but it is not required.
 */
$subject_description=array(
	"SA3 PM1", 
	"SA3 PM2",
	"SA3 PM3",
	"SA3 PM4",
	"SA3 PM5"
);

/*
 * Hostnames where results are stored in RRD files. The web server will contact
 * these hosts to retrieve results. It can be a central station that 
 * communicates with remote monitoring stations via DiMAPI. Or it can be 
 * individual remote monitoring stations directly.
 */
$subject_hostname=array(
	"sa3-pm1.geant2.net",
	"sa3-pm2.geant2.net",
	"sa3-pm3.geant2.net",
	"sa3-pm4.geant2.net",
	"sa3-pm5.geant2.net"
);

/* If 1 then the subject is disabled (shown gray in the user interface) */
$subject_disabled=array( 0, 0, 0, 0, 0 );

/* The following is optional configuration - you do not need to include it */

/* Picture of the monitored network to be shown in the user interface */
define(NET_IMG, "GEANT2_logo_72dpi_RGB.jpg");

/* END OF USER CONFIGURATION SECTION */

/* define(GRAPH_SCRIPT, ABW_DIR . "/bin/rrd_graph_all.sh");
define(GRAPH_DIR, WEB_DIR . "/graph");
define(REMOTE_GRAPH_DIR, ABW_DIR . "/graph"); */

$GRAPH_SCRIPT=ABW_DIR . "/bin/rrd_graph_all.sh";
$GRAPH_DIR=WEB_DIR . "/graph";
$REMOTE_GRAPH_DIR=ABW_VAR_DIR . "/graph";
$REMOTE_USERNAME=REMOTE_USERNAME;

?>
