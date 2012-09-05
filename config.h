/* config.h.  Generated from config.h.in by configure.  */
/* config.h.in.  Generated from configure.ac by autoheader.  */

/* configuration directory */
#define CONFDIR "/usr/local/etc/mapi"

/* configuration file */
#define CONF_FILE "mapi.conf"

/* directory for drivers and function librarues */
#define DATADIR "/usr/local/share/mapi"

/* keep debugging on during beta testing */
#define DEBUG 1

/* Support for distributed monitoring */
#define DIMAPI 1

/* SSL support for DiMAPI */
/* #undef DIMAPISSL */

/* Define to 1 if you have the <arpa/inet.h> header file. */
#define HAVE_ARPA_INET_H 1

/* Define to 1 if you have the <dlfcn.h> header file. */
#define HAVE_DLFCN_H 1

/* Define to 1 if you have the <fcntl.h> header file. */
#define HAVE_FCNTL_H 1

/* Data type */
#define HAVE_INT16_T 1

/* Data type */
#define HAVE_INT32_T 1

/* Data type */
#define HAVE_INT64_T 1

/* Data type */
#define HAVE_INT8_T 1

/* Define to 1 if you have the <inttypes.h> header file. */
#define HAVE_INTTYPES_H 1

/* Define to 1 if you have the `m' library (-lm). */
#define HAVE_LIBM 1

/* Define to 1 if you have the `nids' library (-lnids). */
#define HAVE_LIBNIDS 1

/* Define to 1 if you have the `pcre' library (-lpcre). */
#define HAVE_LIBPCRE 1

/* Define to 1 if you have the `rt' library (-lrt). */
/* #undef HAVE_LIBRT */

/* Define to 1 if you have the <malloc.h> header file. */
#define HAVE_MALLOC_H 1

/* Define to 1 if you have the <memory.h> header file. */
#define HAVE_MEMORY_H 1

/* Define to 1 if you have the <netdb.h> header file. */
#define HAVE_NETDB_H 1

/* Define to 1 if you have the <netinet/in.h> header file. */
#define HAVE_NETINET_IN_H 1

/* Define to 1 if you have the <net/ethernet.h> header file. */
#define HAVE_NET_ETHERNET_H 1

/* whether we are using openssl */
/* #undef HAVE_OPENSSL */

/* Define to 1 if you have the <stddef.h> header file. */
#define HAVE_STDDEF_H 1

/* Define to 1 if you have the <stdint.h> header file. */
#define HAVE_STDINT_H 1

/* Define to 1 if you have the <stdlib.h> header file. */
#define HAVE_STDLIB_H 1

/* Define to 1 if you have the <strings.h> header file. */
#define HAVE_STRINGS_H 1

/* Define to 1 if you have the <string.h> header file. */
#define HAVE_STRING_H 1

/* Define to 1 if you have the <syslog.h> header file. */
#define HAVE_SYSLOG_H 1

/* Define to 1 if you have the <sys/ethernet.h> header file. */
/* #undef HAVE_SYS_ETHERNET_H */

/* Define to 1 if you have the <sys/file.h> header file. */
#define HAVE_SYS_FILE_H 1

/* Define to 1 if you have the <sys/socket.h> header file. */
#define HAVE_SYS_SOCKET_H 1

/* Define to 1 if you have the <sys/stat.h> header file. */
#define HAVE_SYS_STAT_H 1

/* Define to 1 if you have the <sys/time.h> header file. */
#define HAVE_SYS_TIME_H 1

/* Define to 1 if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H 1

/* Data type */
#define HAVE_UINT16_T 1

/* Data type */
#define HAVE_UINT32_T 1

/* Data type */
#define HAVE_UINT8_T 1

/* Define to 1 if you have the <unistd.h> header file. */
#define HAVE_UNISTD_H 1

/* Data type */
#define HAVE_U_INT16_T 1

/* Data type */
#define HAVE_U_INT32_T 1

/* Data type */
#define HAVE_U_INT64_T 1

/* Data type */
#define HAVE_U_INT8_T 1

/* Define to 1 if you have the <zlib.h> header file. */
#define HAVE_ZLIB_H 1

/* Define to the sub-directory in which libtool stores uninstalled libraries.
   */
#define LT_OBJDIR ".libs/"

/* mapicommd SSL certificate */
#define MAPICOMMD_SSL_CERT_FILE "mapicommd_cert.pem"

/* mapicommd SSL key */
#define MAPICOMMD_SSL_KEY_FILE "mapicommd_key.pem"

/* mapi group name */
#define MAPI_GROUP_NAME "mapi"

/* Name of package */
#define PACKAGE "mapi"

/* Define to the address where bug reports for this package should be sent. */
#define PACKAGE_BUGREPORT "mapi@uninett.no"

/* Define to the full name of this package. */
#define PACKAGE_NAME "mapi"

/* Define to the full name and version of this package. */
#define PACKAGE_STRING "mapi 2.0-beta1"

/* Define to the one symbol short name of this package. */
#define PACKAGE_TARNAME "mapi"

/* Define to the home page for this package. */
#define PACKAGE_URL ""

/* Define to the version of this package. */
#define PACKAGE_VERSION "2.0-beta1"

/* Support for reconnect of client after connection to mapicommd or mapid
   breaks down */
/* #undef RECONNECT */

/* rulerflib is enabled in the build */
/* #undef RULERFLIB_COMPILED */

/* The size of `char', as computed by sizeof. */
#define SIZEOF_CHAR 1

/* The size of `int', as computed by sizeof. */
#define SIZEOF_INT 4

/* The size of `long int', as computed by sizeof. */
#define SIZEOF_LONG_INT 4

/* The size of `long long int', as computed by sizeof. */
#define SIZEOF_LONG_LONG_INT 8

/* The size of `short int', as computed by sizeof. */
#define SIZEOF_SHORT_INT 2

/* Define to 1 if you have the ANSI C header files. */
#define STDC_HEADERS 1

/* trackflib is enabled in the build */
#define TRACKFLIB_COMPILED 1

/* easier debugging using valgrind */
#define VALGRIND 1

/* Version number of package */
#define VERSION "2.0-beta1"

/* support for authentication */
/* #undef WITH_AUTHENTICATION */

/* if DAG cards are supported */
/* #undef WITH_DAG */

/* enable function statistics */
/* #undef WITH_FUNCT_STATS */

/* enable mapidlib locking */
#define WITH_LOCKING 1

/* support for functions that modify packets */
#define WITH_MODIFY_PKTS 1

/* if NAPATECH cards are supported */
/* #undef WITH_NAPATECH */

/* if Napatech_x cards are supported */
/* #undef WITH_NAPATECH_X */
