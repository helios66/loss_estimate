#define	UNIXSTR_PATH	"/tmp/unix.str"	/* Unix domain stream */
#define	MAXLINE		4096	/* max text line length */

void err_quit(const char *, ...);
void err_sys(const char *, ...);
void Writen(int fd, void *ptr, size_t nbytes);
ssize_t Readn(int fd, void *ptr, size_t nbytes);
ssize_t Readline(int fd, void *ptr, size_t maxlen);
