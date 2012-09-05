/*
 *  Copyright (C) 2002-03 Luca Deri <deri@ntop.org>
 *
 *  			  http://www.ntop.org/
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

/* ********************************************** */

#ifdef WIN32
#define nprobe_sleep(a /* sec */) waitForNextEvent(1000*a /* ms */)
extern unsigned long waitForNextEvent(unsigned long ulDelay /* ms */);
extern void initWinsock32();
extern short isWinNT();
#define close(fd) closesocket(fd)
#else
int nprobe_sleep(int secs);
#endif

extern unsigned long long htonll(unsigned long long n);

extern void traceEvent(np_ctxt_t *npctxt, int eventTraceLevel, char* file, int line, char * format, ...);
extern int snprintf(char *string, size_t maxlen, const char *format, ...);
extern void checkHostFingerprint(char *fingerprint, char *osName, int osNameLen);
extern u_short ip2AS(IpAddress ip);
extern void readASs(char *path);
extern void nprintf(FILE *stream, char *fmt, HashBucket *theFlow, int direction);
extern void flowPrintf(np_ctxt_t *npctxt, V9TemplateId **templateList, 
		       char *outBuffer, int *outBufferBegin, int *outBufferMax,
		       int *numElements, char buildTemplate,
		       HashBucket *theFlow, int direction, int addTypeLen);
extern void compileTemplate(np_ctxt_t *npctxt, char *_fmt, 
			    V9TemplateId **templateList, int templateElements);
extern long unsigned int toMs(unsigned long long theTime);
extern u_int32_t msTimeDiff(unsigned long long end, unsigned long long begin);
extern u_int32_t usTimeDiff(unsigned long long end, unsigned long long begin);
extern unsigned long pktsDropped(np_ctxt_t *npctxt);
extern unsigned int ntop_sleep(unsigned int secs);
extern HashBucket* getListHead(HashBucket **list);
extern void addToList(HashBucket *bkt, HashBucket **list);
extern void addToListEnd(HashBucket *bkt, HashBucket **list, HashBucket **listend);
