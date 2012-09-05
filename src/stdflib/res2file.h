#ifndef _res2file_h
#define _res2file_h

//R2F_RAW: results are stored in a binary format
//R2F_ULLSTR: unsigned long long values are converted to strings
//R2F_ULLSEC: unsigned long long values are converted to a string representing number of seconds
//R2F_STATS: stores the results from the STATS functions as a string

enum res2file_format {
  R2F_RAW, R2F_ULLSTR, R2F_ULLSEC, R2F_STATS
};

#endif
