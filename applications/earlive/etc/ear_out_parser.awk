#!/usr/bin/awk -f

# This script gets monitor outputs and produces
# the appropriate lines in the data file.

BEGIN { 
    alert_id=ALERTID; 
    ear_dir=EARDIR;
    time=0;
	sl=SUBLEN; dt=DESTTHR; tt=TIMETHR;
}

/LOG:/ { 
    $1=strftime("%D %T :", systime()); 
    print $0 >> (ear_dir "log.txt");
    fflush(ear_dir "log.txt");
	if ($2 == "Param") {
		split($6, ar, "/");
		sl = ar[1];
		dt = ar[2];
		tt = ar[3];
	}
}

/ALERT/ {
    while( $1 != ":ALERT") {
		print $0 >> (ear_dir "alerts/" alert_id);
		getline;
    }
    close(ear_dir "alerts/" alert_id);
    alert_id++;
}

/STATUS/ {
    while( $1 != ":STATUS") {
		getline;
		if ($1 == "bytes_processed:")
	    	bytes = $2;
		else if ($1 == "similarity:")
	    	sim = $2;
    }
# const length 52 bytes
    printf "%9d %13d %7d %6d %4d %2d %4d\n", 
		time, bytes, sim, alert_id, 
		sl, dt, tt >> (ear_dir "data");
    fflush(ear_dir "data");
    time++;
}

END {
    print strftime("%D %T :", systime()), 
		"EAR terminated!\n" >> (ear_dir "log.txt");
}

