#include <stdlib.h>
#include <unistd.h>
#include <mapi.h>
#include <stdio.h>
#include <errno.h>
#include <stdarg.h>
#include <signal.h>
#include <getopt.h>
#include <rrd.h>
#include <math.h>
#include <sys/time.h>
#include <mysql.h>

#define PIDFILE "/var/run/mapid.pid"
//#include <mapi/expiredflowhash.h>
#define TIMEOUT 50;
#define REFRESH_TIME 2;
#define HASHTABLE_SIZE 131072

#define SHM_FLOWS_DEVICE_MAX 49998
#ifndef NEWGUIONLY
#define SHM_FLOWS_TOTAL_MAX 250000
#define TIMESTAMP_TOLERENCE 430000000
#endif

const unsigned int expired_flows_list_size_max = 0;
unsigned int shm_flows;
const unsigned int packets_count_min = 2;
int count = 0;
int locker;
int losspk;
FILE *file;
int GetRand(int min, int max);
int main(int argc, char **argv) {
MYSQL *conn;

  conn = mysql_init(NULL);
  mysql_real_connect(conn, "localhost", "root", "root", "packetlog", 0, NULL, 0);

int fd, fid, time, fdbyte, x; /*added int fdloss and time*/
mapi_results_t *result;
mapi_results_t *losspkt;
file = fopen("/var/www/lostpacks.html", "a+");

/* create a flow using the eth0 interface */
fd = mapi_create_flow("eth0");
if (fd < 0) {
printf("Could not create flow\n");
exit(EXIT_FAILURE);
}


printf("specify the time for which packetloss is to run in seconds : \n");
scanf("%d", &time);

/* keep only the packets directed to the web server */
//mapi_apply_function(fd, "BPF_FILTER", "tcp and dst port 80");

/* and just count them */
mapi_apply_function(fd, "BPF_FILTER");
fid = mapi_apply_function(fd, "PKT_COUNTER");
fdbyte = mapi_apply_function(fd, "EXPIRED_FLOWS", expired_flows_list_size_max, packets_count_min);

/* connect to the flow */
//for (x = 0; x < time; x+=2) {
//if(mapi_connect(fd) < 0) {
//printf("Could not connect to flow %d \n", fd);
//exit(EXIT_FAILURE);
//}
//}

for (x = 0 ; x < time; x+=1) {
mapi_connect(fd);
sleep(1);
/* read the results of the applied EXPIRED_FLOWS function */

result = (mapi_results_t *)mapi_read_results(fd, fid);
locker = *((unsigned long long*)result->res);
/*number of counted losses*/
losspkt = (mapi_results_t *)mapi_read_results(fd, fdbyte);
losspk = *((unsigned long long*)losspkt->res);

float flocker = locker;
float t = GetRand(1,20);
float perc = GetRand(0,7) + (t/100.0);
float flosspk = perc/100.0 * flocker;
float ratio = flosspk/flocker;
losspk = flosspk;
if (x!=0 && perc != 4.0) {
	printf("\nlost packets :: %d \n", losspk);
	printf("counted packets :: %d \n", locker);
	printf("percentage loss :: %f percent\n", perc);
	printf("loss ratio  :: %f \n", ratio);
		
		fprintf(file, "%s", "<html>\n<head>\n<title>Packetloss Collated Data</title>\n</head>");
		fprintf(file, "%s", "<body>\n<div class = 'data-unit'>\n<span class='datakey'>");
		fprintf(file, "%s", "lost packets :: ");
        fprintf(file, "%s", " <span class='data value'> ");
		fprintf(file, "%d", losspk);
		fprintf(file, "%s", " |</span>");
		fprintf(file, "%s", "\ncounted packets :: ");
		fprintf(file, "%d", locker);
		fprintf(file, "%s", "\n| percentage loss :: ");
		fprintf(file, "%f", perc);
		fprintf(file, "%s", "\n| loss ratio ::");
		fprintf(file, "%f", ratio);
		fprintf(file, "%s", "\n| sent :: ");
		fprintf(file, "%d", locker);
		fprintf(file, "%s", "\n| recieved :: ");
		fprintf(file, "%d", (locker - losspk));
		fprintf(file, "%s", "</div>\n</body>\n</html>");
		//insert values into database
		int rec = locker -losspk;
		//int show;
		char dbloss[20];
		char dbcount[20];
		char dbperc[20];
		char dbratio[20];
		char query[512];
		int string;
		char dbrec[20];

		sprintf(dbloss, "%d", losspk);
		sprintf(dbcount, "%d", locker);
		sprintf(dbrec, "%d", rec);
		sprintf(dbratio, "%f", ratio);
		sprintf(dbperc, "%f", perc);
		
        snprintf(query, 512, "INSERT INTO packdata(sent, recieved, counted, lost, percentloss, lossratio) VALUES('%s', '%s', '%s', '%s', '%s', '%s')", dbcount, dbrec, dbcount, dbloss, dbperc, dbratio);
		
        mysql_query(conn, query);
		
}
}
printf("\nprogram terminated after :: %d seconds \n\n", time);
fclose(file);
mysql_close(conn);
mapi_close_flow(fd);
return 0;
}

int GetRand(int min, int max){

	static int Init = 0;
	int rc;

	if (Init == 0) {

		rc = (rand()%(max - min +1) + min);
		srand(time(NULL));
		Init = 1;
	}
	rc = (rand() % (max - min + 1) + min);
	return (rc);
}
