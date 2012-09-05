AC_PREREQ([2.59])
AC_INIT([mapi], [2.0-beta1], [mapi@uninett.no])
AM_CONFIG_HEADER(config.h)
AC_CONFIG_SRCDIR([src/mapid.c])
AC_CONFIG_AUX_DIR(config)
AM_INIT_AUTOMAKE(foreign no-dependencies no-installinfo)

# Checks for programs
AC_PROG_CC
AC_PROG_INSTALL
AC_PATH_PROG(ac_mapi_groupadd, groupadd, no, $PATH:/sbin:/usr/sbin:/usr/local/sbin:/usr/ucb)
if test $ac_mapi_groupadd = no ; then
	AC_MSG_WARN("groupadd not found, so a MAPI group will not be created.")
else
	GROUPADD="$ac_mapi_groupadd"
	AC_SUBST(GROUPADD)
fi

AC_MSG_NOTICE([libtool -----------------------------------------------------])
# Turn off static libraries during beta-testing, since they
# make the build process take too long.
AC_DISABLE_STATIC
# Check for dlopen support
AC_LIBTOOL_DLOPEN
# Configure libtool
AC_PROG_LIBTOOL

# Checks for C headers
AC_MSG_NOTICE([header files ------------------------------------------------])
AC_HEADER_STDC
AC_CHECK_HEADERS([arpa/inet.h fcntl.h malloc.h netdb.h netinet/in.h stddef.h stdint.h stdlib.h string.h sys/file.h sys/socket.h sys/time.h syslog.h unistd.h zlib.h sys/ethernet.h net/ethernet.h])

# Checks for data types
AC_CHECK_SIZEOF(char, 1)
AC_CHECK_SIZEOF(short int, 2)
AC_CHECK_SIZEOF(int, 4)
AC_CHECK_SIZEOF(long int, 4)
AC_CHECK_SIZEOF(long long int, 8)

AC_CACHE_CHECK([for intXX_t types], ac_cv_have_intxx_t, [
	AC_TRY_COMPILE(
		[ #include <sys/types.h> ], 
		[ int8_t a; int16_t b; int32_t c; a = b = c = 1;], 
		[ ac_cv_have_intxx_t="yes" ],
		[ ac_cv_have_intxx_t="no" ]
	)
])
if test "x$ac_cv_have_intxx_t" = "xyes" ; then
	AC_DEFINE(HAVE_INT8_T, 1, [Data type])
	AC_DEFINE(HAVE_INT16_T, 1, [Data type])
	AC_DEFINE(HAVE_INT32_T, 1, [Data type])
	have_intxx_t=1
fi

if (test -z "$have_intxx_t" && test "x$ac_cv_header_stdint_h" = "xyes")
then
    AC_MSG_CHECKING([for intXX_t types in stdint.h])
	AC_TRY_COMPILE(
		[ #include <stdint.h> ], 
		[ int8_t a; int16_t b; int32_t c; a = b = c = 1;], 
		[
			AC_DEFINE(HAVE_INT8_T, 1, [Data type])
			AC_DEFINE(HAVE_INT16_T, 1, [Data type])
			AC_DEFINE(HAVE_INT32_T, 1, [Data type])
			AC_MSG_RESULT(yes)
		],
		[ AC_MSG_RESULT(no) ]
	)
fi

AC_CACHE_CHECK([for int64_t type], ac_cv_have_int64_t, [
	AC_TRY_COMPILE(
		[ #include <sys/types.h> ], 
		[ int64_t a; a = 1;], 
		[ ac_cv_have_int64_t="yes" ],
		[ ac_cv_have_int64_t="no" ]
	)
])
if test "x$ac_cv_have_int64_t" = "xyes" ; then
	AC_DEFINE(HAVE_INT64_T, 1, [Data type])
	have_int64_t=1
fi
	
if test -z "$have_int64_t" ; then
    AC_MSG_CHECKING([for int64_t type in sys/socket.h])
	AC_TRY_COMPILE(
		[ #include <sys/socket.h> ], 
		[ int64_t a; a = 1],
		[
			AC_DEFINE(HAVE_INT64_T, 1, [Data type])
			AC_MSG_RESULT(yes)
		],
		[ AC_MSG_RESULT(no) ]
	)
fi

AC_CACHE_CHECK([for u_intXX_t types], ac_cv_have_u_intxx_t, [
	AC_TRY_COMPILE(
		[ #include <sys/types.h> ], 
		[ u_int8_t a; u_int16_t b; u_int32_t c; a = b = c = 1;], 
		[ ac_cv_have_u_intxx_t="yes" ],
		[ ac_cv_have_u_intxx_t="no" ]
	)
])
if test "x$ac_cv_have_u_intxx_t" = "xyes" ; then
	AC_DEFINE(HAVE_U_INT8_T, 1, [Data type])
	AC_DEFINE(HAVE_U_INT16_T, 1, [Data type])
	AC_DEFINE(HAVE_U_INT32_T, 1, [Data type])
	have_u_intxx_t=1
fi

if test -z "$have_u_intxx_t" ; then
    AC_MSG_CHECKING([for u_intXX_t types in sys/socket.h])
	AC_TRY_COMPILE(
		[ #include <sys/socket.h> ], 
		[ u_int8_t a; u_int16_t b; u_int32_t c; a = b = c = 1;], 
		[
			AC_DEFINE(HAVE_U_INT8_T, 1, [Data type])
			AC_DEFINE(HAVE_U_INT16_T, 1, [Data type])
			AC_DEFINE(HAVE_U_INT32_T, 1, [Data type])
			AC_MSG_RESULT(yes)
		],
		[ AC_MSG_RESULT(no) ]
	)
fi

AC_CACHE_CHECK([for u_int64_t types], ac_cv_have_u_int64_t, [
	AC_TRY_COMPILE(
		[ #include <sys/types.h> ], 
		[ u_int64_t a; a = 1;], 
		[ ac_cv_have_u_int64_t="yes" ],
		[ ac_cv_have_u_int64_t="no" ]
	)
])
if test "x$ac_cv_have_u_int64_t" = "xyes" ; then
	AC_DEFINE(HAVE_U_INT64_T, 1, [Data type])
	have_u_int64_t=1
fi

if test -z "$have_u_intxx_t" ; then
	AC_CACHE_CHECK([for uintXX_t types], ac_cv_have_uintxx_t, [
		AC_TRY_COMPILE(
			[ #include <sys/types.h> ], 
			[ uint8_t a; uint16_t b; uint32_t c; a = b = c = 1; ], 
			[ ac_cv_have_uintxx_t="yes" ],
			[ ac_cv_have_uintxx_t="no" ]
		)
	])
	if test "x$ac_cv_have_uintxx_t" = "xyes" ; then
		AC_DEFINE(HAVE_UINT8_T, 1, [Data type])
		AC_DEFINE(HAVE_UINT16_T, 1, [Data type])
		AC_DEFINE(HAVE_UINT32_T, 1, [Data type])
	fi
fi

if test -z "$have_uintxx_t" ; then
    AC_MSG_CHECKING([for uintXX_t types in stdint.h])
	AC_TRY_COMPILE(
		[ #include <stdint.h> ], 
		[ uint8_t a; uint16_t b; uint32_t c; a = b = c = 1;], 
		[
			AC_DEFINE(HAVE_UINT8_T, 1, [Data type])
			AC_DEFINE(HAVE_UINT16_T, 1, [Data type])
			AC_DEFINE(HAVE_UINT32_T, 1, [Data type])
			AC_MSG_RESULT(yes)
		],
		[ AC_MSG_RESULT(no) ]
	)
fi

# $prefix stores the value of the --prefix command line option, or NONE if
# the option wasn't set. In the latter case, set it to the default, so that
# we can use it to expand directories now.
if test "x$prefix" = "xNONE"; then
	prefix=$ac_default_prefix
fi

AC_MSG_NOTICE([MAPI options ------------------------------------------------])

AC_DEFINE(CONF_FILE, "mapi.conf", [configuration file])
AC_DEFINE(MAPICOMMD_SSL_KEY_FILE, "mapicommd_key.pem", [mapicommd SSL key])
AC_DEFINE(MAPICOMMD_SSL_CERT_FILE, "mapicommd_cert.pem", [mapicommd SSL certificate])
# development defines - leave them enabled for now
AC_DEFINE(DEBUG, 1, [keep debugging on during beta testing])
AC_DEFINE(VALGRIND, 1, [easier debugging using valgrind])

# mapi user group name
AC_ARG_VAR(MAPI_GROUP, [Name of the MAPI user group (default: 'mapi')])
if test x$MAPI_GROUP = x; then
	MAPI_GROUP=mapi;
fi
AC_DEFINE_UNQUOTED(MAPI_GROUP_NAME, "${MAPI_GROUP}", [mapi group name])

# in the end will contain all the enabled MAPI function libraries
MAPI_FUNC_LIBS="stdflib.so"

# DiMAPI
AC_MSG_CHECKING([if distributed monitoring (DiMAPI) is enabled])
AC_ARG_ENABLE(dimapi,
AS_HELP_STRING([--enable-dimapi], [Enable support for distributed monitoring (DiMAPI)]),
[case "${enableval}" in
	yes) dimapi=true ;;
	no)  dimapi=false ;;
	*) AC_MSG_ERROR(bad value ${enableval} for --enable-dimapi) ;;
esac], [dimapi=false])
AM_CONDITIONAL(BINARY_DIMAPI, test x$dimapi = xtrue)
AM_CONDITIONAL(LIB_DIMAPI, test x$dimapi = xtrue)
if test x$dimapi = xtrue; then
	AC_DEFINE(DIMAPI, 1, [Support for distributed monitoring])
	AC_MSG_RESULT(yes)
else
	AC_MSG_RESULT(no)
fi

# Reconnection
AC_MSG_CHECKING([if reconnection of client is enabled])
AC_ARG_ENABLE(reconnect,
AS_HELP_STRING([--enable-reconnect], [Enable support for reconnection of client after connection to mapicommd or mapid breaks down]),
[case "${enableval}" in
	yes) reconnect=true ;;
	no)  reconnect=false ;;
	*) AC_MSG_ERROR(bad value ${enableval} for --enable-reconnect) ;;
esac], [reconnect=false])
AM_CONDITIONAL(BINARY_RECONNECT, test x$reconnect = xtrue)
if test x$reconnect = xtrue; then
	AC_DEFINE(RECONNECT, 1, [Support for reconnect of client after connection to mapicommd or mapid breaks down])
	AC_MSG_RESULT(yes)
else
	AC_MSG_RESULT(no)
fi
# for etc/Makefile.am
AM_CONDITIONAL(RECONNECTION_IS_ENABLED, test x$reconnect = xtrue)

# SSL sockets (only for DiMAPI)
if test x$dimapi = xtrue; then
	AC_MSG_CHECKING([if SSL for DiMAPI is enabled])
fi
AC_ARG_ENABLE(ssl,
	AS_HELP_STRING([--enable-ssl], [Enable encryption of DiMAPI traffic]),
	[
		if test x$dimapi = xfalse; then
			if test x$enableval = xyes; then
				AC_MSG_ERROR(Please use --enable-ssl only in conjunction with --enable-dimapi. You don't need to enable SSL if you are not going to use DiMAPI)
			fi
		fi
		case "${enableval}" in
			yes) ssl=true ;;
			no)  ssl=false ;;
			*) AC_MSG_ERROR(bad value ${enableval} for --enable-ssl) ;;
		esac
	],
	[
		ssl=false
	]
)
if test x$dimapi = xtrue; then
	if test x$ssl = xtrue; then
		AC_DEFINE(DIMAPISSL, 1, [SSL support for DiMAPI])
		AC_MSG_RESULT(yes)
	else
		AC_MSG_RESULT(no)
	fi
fi
# for etc/Makefile.am
AM_CONDITIONAL(SSL_IS_ENABLED, test x$ssl = xtrue)

# DAG support
AC_MSG_CHECKING(if DAG cards support is enabled)
AC_ARG_ENABLE(dag,
AS_HELP_STRING([--enable-dag], [Enable support for Endace's DAG cards]),
[case "${enableval}" in
	yes) dag=true ;;
	no)  dag=false ;;
	*) AC_MSG_ERROR(bad value ${enableval} for --enable-dag) ;;
esac], [dag=false])
AM_CONDITIONAL(DRIVER_DAG, test x$dag = xtrue)
AM_CONDITIONAL(BINARY_DAGFLIB, test x$dag = xtrue)
if test x$dag = xtrue; then
	MAPI_CONF_DAG_ENTRY=$srcdir/config/mapi.conf.dag.entry
	MAPI_FUNC_LIBS="${MAPI_FUNC_LIBS}:dagflib.so"
	AC_DEFINE(WITH_DAG, 1, [if DAG cards are supported])
	AC_MSG_RESULT(yes)
else
	MAPI_CONF_DAG_ENTRY=/dev/null
	AC_MSG_RESULT(no)
fi
AC_SUBST_FILE(MAPI_CONF_DAG_ENTRY)

# ENP2611 support
AC_MSG_CHECKING(if ENP2611 cards support is enabled)
AC_ARG_ENABLE(enp2611,
AS_HELP_STRING([--enable-enp2611], [Enable support for ENP2611 cards]),
[case "${enableval}" in
	yes) enp2611=true ;;
	no)  enp2611=false ;;
	*) AC_MSG_ERROR(bad value ${enableval} for --enable-enp2611) ;;
esac], [enp2611=false])
AM_CONDITIONAL(DRIVER_ENP2611, test x$enp2611 = xtrue)
AM_CONDITIONAL(BINARY_ENP2611FLIB, test x$enp2611 = xtrue)


# Napatech-X support
AC_MSG_CHECKING(if Napatech-X cards support is enabled)
AC_ARG_ENABLE(napatech_x,
AS_HELP_STRING([--enable-napatech_x], [Enable support for Napatech-x cards]),
[case "${enableval}" in
	yes) napatech_x=true ;;
	no)  napatech_x=false ;;
	*) AC_MSG_ERROR(bad value ${enableval} for --enable-napatech_x) ;;
esac], [napatech_x=false])
AM_CONDITIONAL(DRIVER_NAPATECH_X, test x$napatech_x = xtrue)
AM_CONDITIONAL(BINARY_NAPATECHFLIB, test x$napatech_x = xtrue)
if test x$napatech_x = xtrue; then
	MAPI_CONF_NAPATECH_X_ENTRY=$srcdir/config/mapi.conf.napatech_x.entry
	MAPI_FUNC_LIBS="${MAPI_FUNC_LIBS}:napatechflib.so"
	AC_DEFINE(WITH_NAPATECH_X, 1, [if Napatech_x cards are supported])
	AC_MSG_RESULT(yes)
else
	MAPI_CONF_NAPATECH_X_ENTRY=/dev/null
	AC_MSG_RESULT(no)
fi
AC_SUBST_FILE(MAPI_CONF_NAPATECH_X_ENTRY)

# NAPATECH support - NT cards
AC_MSG_CHECKING(if NAPATECH cards support is enabled)
AC_ARG_ENABLE(napatech,
AS_HELP_STRING([--enable-napatech], [Enable support for NAPATECH NT cards]),
[case "${enableval}" in
        yes) napatech=true ;;
        no)  napatech=false ;;
        *) AC_MSG_ERROR(bad value ${enableval} for --enable-napatech) ;;
esac], [napatech=false])
AM_CONDITIONAL(DRIVER_NAPATECH, test x$napatech = xtrue)
AM_CONDITIONAL(BINARY_NAPATECHFLIB, test x$napatech = xtrue)
# AM_CONDITIONAL(PRECLASSIFICATION, test x$dag = xtrue)
if test x$napatech = xtrue; then
        MAPI_CONF_NAPATECH_ENTRY=$srcdir/config/mapi.conf.napatech.entry
        MAPI_FUNC_LIBS="${MAPI_FUNC_LIBS}:napatechflib.so"
        # AC_DEFINE(PRECLASSIFICATION, 1, [hardware preliminary packet classification])
        AC_DEFINE(WITH_NAPATECH, 1, [if NAPATECH cards are supported])
        AC_MSG_RESULT(yes)
else
        MAPI_CONF_NAPATECH_ENTRY=/dev/null
        AC_MSG_RESULT(no)
fi
AC_SUBST_FILE(MAPI_CONF_NAPATECH_ENTRY)


# optional MAPI function libraries

# trackflib
AC_MSG_CHECKING(if the traffic characterization library is enabled)
AC_ARG_ENABLE(trackflib,
AS_HELP_STRING([--enable-trackflib], [Build the traffic characterization library]),
[case "${enableval}" in
	yes) trackflib=true ;;
	no)  trackflib=false ;;
	*) AC_MSG_ERROR(bad value ${enableval} for --enable-trackflib) ;;
esac], [trackflib=false])
AM_CONDITIONAL(BINARY_TRACKFLIB, test x$trackflib = xtrue)
if test x$trackflib = xtrue; then
	MAPI_FUNC_LIBS="${MAPI_FUNC_LIBS}:trackflib.so"
	AC_DEFINE(TRACKFLIB_COMPILED, 1, [trackflib is enabled in the build])
	AC_MSG_RESULT(yes)
else
	AC_MSG_RESULT(no)
fi

# rulerflib
AC_MSG_CHECKING(if the Ruler interface library is enabled)
AC_ARG_ENABLE(rulerflib,
AS_HELP_STRING([--enable-rulerflib], [Build the Ruler interface library]),
[case "${enableval}" in
	yes) rulerflib=true ;;
	no)  rulerflib=false ;;
	*) AC_MSG_ERROR(bad value ${enableval} for --enable-rulerflib) ;;
esac], [rulerflib=false])
AM_CONDITIONAL(BINARY_RULERFLIB, test x$rulerflib = xtrue)
if test x$rulerflib = xtrue; then
	MAPI_FUNC_LIBS="${MAPI_FUNC_LIBS}:rulerflib.so"
	AC_DEFINE(WITH_MODIFY_PKTS, 1, [support for functions that modify packets])
	AC_DEFINE(RULERFLIB_COMPILED, 1, [rulerflib is enabled in the build])
	AC_MSG_RESULT(yes)
else
	AC_MSG_RESULT(no)
fi

# anonflib
AC_MSG_CHECKING(if the anonymization library is enabled)
AC_ARG_ENABLE(anonflib,
AS_HELP_STRING([--enable-anonflib], [Build the traffic anonymization library]),
[case "${enableval}" in
	yes) anonflib=true ;;
	no)  anonflib=false ;;
	*) AC_MSG_ERROR(bad value ${enableval} for --enable-anonflib) ;;
esac], [anonflib=false])
AM_CONDITIONAL(BINARY_ANONFLIB, test x$anonflib = xtrue)
if test x$anonflib = xtrue; then
	MAPI_FUNC_LIBS="${MAPI_FUNC_LIBS}:anonflib.so"
	AC_DEFINE(WITH_MODIFY_PKTS, 1, [support for functions that modify packets])
	AC_MSG_RESULT(yes)
else
	AC_MSG_RESULT(no)
fi

# appmon
AC_MSG_CHECKING(if the appmon application is enabled)
AC_ARG_ENABLE(appmon,
AS_HELP_STRING([--enable-appmon], [Build the appmon application]),
[case "${enableval}" in
	yes) appmon=true ;;
	no)  appmon=false ;;
	*) AC_MSG_ERROR(bad value ${enableval} for --enable-appmon) ;;
esac], [appmon=false])
AM_CONDITIONAL(BINARY_APPMON, test x$appmon = xtrue)
if test x$appmon = xtrue; then
	AC_MSG_RESULT(yes)
else
	AC_MSG_RESULT(no)
fi

# ipfixflib
AC_MSG_CHECKING(if the ipfix library is enabled)
AC_ARG_ENABLE(ipfixflib,
AS_HELP_STRING([--enable-ipfixflib], [Build the NetFlow export library]),
[case "${enableval}" in
	yes) ipfixflib=true ;;
	no)  ipfixflib=false ;;
	*) AC_MSG_ERROR(bad value ${enableval} for --enable-ipfixflib) ;;
esac], [ipfixflib=false])
AM_CONDITIONAL(BINARY_IPFIXFLIB, test x$ipfixflib = xtrue)
if test x$ipfixflib = xtrue; then
	MAPI_CONF_IPFIXFLIB_ENTRY=$srcdir/config/mapi.conf.ipfixflib.entry
	MAPI_FUNC_LIBS="${MAPI_FUNC_LIBS}:ipfixflib.so"
	AC_MSG_RESULT(yes)
else
	MAPI_CONF_IPFIXFLIB_ENTRY=/dev/null
	AC_MSG_RESULT(no)
fi
AC_SUBST_FILE(MAPI_CONF_IPFIXFLIB_ENTRY)

# extraflib
AC_MSG_CHECKING(if the extra functions library is enabled)
AC_ARG_ENABLE(extraflib,
AS_HELP_STRING([--enable-extraflib], [Build the extra functions library]),
[case "${enableval}" in
	yes) extraflib=true ;;
	no)  extraflib=false ;;
	*) AC_MSG_ERROR(bad value ${enableval} for --enable-extraflib) ;;
esac], [extraflib=false])
AM_CONDITIONAL(BINARY_EXTRAFLIB, test x$extraflib = xtrue)
if test x$extraflib = xtrue; then
	MAPI_FUNC_LIBS="${MAPI_FUNC_LIBS}:extraflib.so"
	# needed by cooking
	AC_DEFINE(WITH_MODIFY_PKTS, 1, [support for functions that modify packets])
	AC_MSG_RESULT(yes)
else
	AC_MSG_RESULT(no)
fi

# a string with all the compiled MAPI function libraries
AC_SUBST(MAPI_FUNC_LIBS)

# Authentication
AC_MSG_CHECKING([if authentication is enabled])
AC_ARG_ENABLE(authentication,
AS_HELP_STRING([--enable-authentication], [Enable support for authentication]),
[
	if test x$dimapi = xfalse; then
		if test x$enableval = xyes; then
			AC_MSG_ERROR(Please use --enable-authentication only in conjunction with --enable-dimapi. You don't need to enable authentication if you are not going to use DiMAPI)
		fi
	fi
	if test x$anonflib = xfalse; then
		if test x$enableval = xyes; then
			AC_MSG_ERROR(Please use --enable-anonflib with authentication because it is neccessary for anonymization functions)
		fi
	fi
	case "${enableval}" in
		yes) authentication=true ;;
		no)	 authentication=false ;;
		*) AC_MSG_ERROR(bad value ${enableval} for --enable-authentication) ;;
	esac
], [authentication=false])
AM_CONDITIONAL(BINARY_AUTHENTICATION, test x$authentication = xtrue)
if test x$authentication = xtrue; then
	AC_DEFINE(WITH_AUTHENTICATION, 1, [support for authentication])
	AC_MSG_RESULT(yes)
else
	AC_MSG_RESULT(no)
fi

# misc options

# function statistics
AC_MSG_CHECKING(if function statistics are enabled)
AC_ARG_ENABLE(funcstats,
AS_HELP_STRING([--enable-funcstats], [Enable function statistics. This option enables packet counters for each applied function]),
[case "${enableval}" in
	yes) funcstats=true ;;
	no)  funcstats=false ;;
	*) AC_MSG_ERROR(bad value ${enableval} for --enable-funcstats) ;;
esac], [funcstats=false])
if test x$funcstats = xtrue; then
	AC_DEFINE(WITH_FUNCT_STATS, 1, [enable function statistics])
	AC_MSG_RESULT(yes)
else
	AC_MSG_RESULT(no)
fi

#No locking in mapidlib
AC_MSG_CHECKING(if locking is enabled in mapidlib)
AC_ARG_ENABLE(locking,
   AS_HELP_STRING([--enable-locking], 
   [Enable locking inside mapidlib. May be disabled to increase performance.]),
   enable_locking="$enableval",
   enable_locking=yes)
if test x$enable_locking = xyes; then
	AC_DEFINE(WITH_LOCKING, 1, [enable mapidlib locking])
	AC_MSG_RESULT(yes)
else
	AC_MSG_RESULT(no)
fi


# Checks for libraries
AC_MSG_NOTICE([libraries ---------------------------------------------------])

#
# libpcap
#
AC_MSG_CHECKING([for libpcap])
AC_ARG_WITH(libpcap,
AS_HELP_STRING([--with-libpcap=DIR], [Manual libpcap path configuration, in case the configuration script can't find it. Search for libpcap in DIR/lib, and for the header file in DIR/include]),
[ case "$withval" in
  yes|no)
     AC_MSG_RESULT(no)
     ;;
  *)
     AC_MSG_RESULT($withval)
     if test -f $withval/pcap.h -a -f $withval/libpcap.a; then
        owd=`pwd`
        if cd $withval; then withval=`pwd`; cd $owd; fi
	PCAPINC="-I$withval -I$withval/bpf"
	PCAPLIB="-L$withval $withval/libpcap.a"
     else
        AC_MSG_ERROR(pcap.h or libpcap.a not found in $withval)
     fi
     ;;
  esac ],
[ if test -f ${prefix}/include/pcap.h; then
     PCAPINC="-I${prefix}/include"
     PCAPLIB="-L${prefix}/lib -lpcap"
  elif test -f /usr/include/pcap/pcap.h; then
     PCAPINC="-I/usr/include/pcap"
     PCAPLIB="-lpcap"
  elif test -f /usr/include/pcap.h; then
     PCAPLIB="-lpcap"
  else
     AC_MSG_RESULT(no)
     AC_MSG_ERROR([libpcap not found - go get it from http://www.tcpdump.org or use the --with-libpcap option if you have installed it in an unusual place])
  fi
  AC_MSG_RESULT(yes) ]
)
AC_SUBST(PCAPINC)
AC_SUBST(PCAPLIB)

#
# libdag (only for --enable-dag)
#
AC_MSG_CHECKING([for libdag])
AC_ARG_WITH(libdag,
AS_HELP_STRING([--with-libdag=DIR], [Manual libdag path configuration, in case the configuration script can't find it. Search for libdag in DIR/lib, and for the header file in DIR/include. Effective only if --enable-dag has been previously specified]),
[ case "$withval" in
	yes|no)
		AC_MSG_RESULT(no)
		;;
	*)
		if test x$dag = xfalse; then
        	AC_MSG_ERROR(Please use --with-libdag only in conjunction with --enable-dag. You don't need to configure libdag if you are not going to use a DAG card.)
		else
			AC_MSG_RESULT($withval)
			if test -f $withval/include/dagapi.h -a -f $withval/lib/libdag.a; then
				owd=`pwd`
				if cd $withval; then withval=`pwd`; cd $owd; fi
				DAGINC="-I$withval/include"
				DAGLIB="-L$withval/lib -ldag -ldagconf -ldagdsm -ladt -lm -ldagema -lpthread"
			else
				AC_MSG_ERROR(dagapi.h or libdag.a not found in $withval/include and $withval/lib)
			fi
	 	fi
		;;
  esac ],
[ if test x$dag = xtrue; then
	if test -f ${prefix}/include/dagapi.h -a -f ${prefix}/lib/libdag.a; then
		DAGINC="-I${prefix}/include"
		DAGLIB="-L${prefix}/lib -ldag -ldagconf -ldagdsm -ladt -lm -ldagema -lpthread"
	elif test -f /usr/local/include/dagapi.h -a -f /usr/local/lib/libdag.a; then
		DAGINC="-I${prefix}/include"
		DAGLIB="-L${prefix}/lib -ldag -ldagconf -ldagdsm -ladt -lm -ldagema -lpthread"
	elif test -f /usr/include/dag/dagapi.h; then
		DAGINC="-I/usr/include/dag"
		DAGLIB="-ldag -ldagconf -ldagdsm -ladt -lm -ldagema -lpthread"
	elif test -f /usr/include/dagapi.h; then
		DAGLIB="-ldag -ldagconf -ldagdsm -ladt -lm -ldagema -lpthread"
	else
		AC_MSG_RESULT(no)
		AC_MSG_ERROR([libdag not found])
	fi
	AC_MSG_RESULT(yes)
  else
	AC_MSG_RESULT(no)
  fi ]
)
AC_SUBST(DAGINC)
AC_SUBST(DAGLIB)


#
# libnapatech (only for --enable-napatech_x)
#
AC_MSG_CHECKING([for libnapatech])
AC_ARG_WITH(libnapatech,
AS_HELP_STRING([--with-libnapatech=DIR], [Manual libnapatech path configuration, in case the configuration script can't find it. Search for libnapatech in DIR/lib, and for the header file in DIR/include and DIR/include/napatech. Effective only if --enable-napatech has been previously specified]),
[ case "$withval" in
	yes|no)
		AC_MSG_RESULT(no)
		;;
	*)
		if ( test x$napatech_x = xfalse && test x$napatech = xfalse ) then
        	AC_MSG_ERROR(Please use --with-libnapatech only in conjunction with --enable-napatech_x or --enable-napatech. You don't need to configure libnapatech if you are not going to use a Napatech card.)
		else
			AC_MSG_RESULT($withval)
			incdir=""
			if test -f $withval/include/NTCommonInterface.h; then
			        incdir=$withval/include
			elif test -f $withval/include/napatech/NTCommonInterface.h; then
			        incdir=$withval/include/napatech
			fi
			if test "x$incdir" != "x"  -a -f $withval/lib/libntcommoninterface.so; then
				owd=`pwd`
				if cd $withval; then withval=`pwd`; cd $owd; fi
				NAPATECHINC="-I$incdir"
				NAPATECHLIB="-L$withval/lib -lntcommoninterface"
			else
				AC_MSG_ERROR(NTCommonInterface.h or libntcommoninterface.so not found in $withval/include and $withval/lib)
			fi
	 	fi
		;;
  esac ],
[ if ( test x$napatech_x = xtrue || test x$napatech = xtrue ) then
	if test -f ${prefix}/include/NTCommonInterface.h -a -f ${prefix}/lib/libntcommoninterface.so; then
		NAPATECHINC="-I${prefix}/include"
		NAPATECHLIB="-L${prefix}/lib -lntcommoninterface"
	elif test -f /opt/napatech/include/NTCommonInterface.h -a -f /opt/napatech/lib/libntcommoninterface.so; then
		NAPATECHINC="-I/opt/napatech/include"
		NAPATECHLIB="-L/opt/napatech/lib -lntcommoninterface"
	elif test -f /opt/napatech/include/napatech/NTCommonInterface.h -a -f /opt/napatech/lib/libntcommoninterface.so; then
		NAPATECHINC="-I/opt/napatech/include/napatech"
		NAPATECHLIB="-L/opt/napatech/lib -lntcommoninterface"
	elif test -f /usr/local/include/NTCommonInterface.h -a -f /usr/local/lib/libntcommoninterface.so; then
		NAPATECHINC="-I/usr/local/include"
		NAPATECHLIB="-L/usr/local/lib -lntcommoninterface"
	elif test -f /usr/local/include/napatech/NTCommonInterface.h -a -f /usr/local/lib/libntcommoninterface.so; then
		NAPATECHINC="-I/usr/local/include/napatech"
		NAPATECHLIB="-L/usr/local/lib -lntcommoninterface"
	elif test -f /usr/include/napatech/NTCommonInterface.h; then
		NAPATECHINC="-I/usr/include/napatech"
		NAPATECHLIB="-lntcommoninterface"
	elif test -f /usr/include/NTCommonInterface.h; then
		NAPATECHLIB="NTCommonInterface.h"
	else
		AC_MSG_RESULT(no)
		AC_MSG_ERROR([libnapatech not found])
	fi
	AC_MSG_RESULT(yes)
  else
	AC_MSG_RESULT(no)
  fi ]
)
AC_SUBST(NAPATECHINC)
AC_SUBST(NAPATECHLIB)


#
# libnids >= 1.21 (only for --enable-extraflib)
#
echo " -----------LIBNIDS -------------------------------"
AC_ARG_WITH(libnids_includes, 
	AS_HELP_STRING([--with-libnids-includes=DIR], [Search for libnids headers in DIR. Effective only if --enable-extraflib has been previously specified]),
	[with_libnids_includes="$withval"],[with_libnids_includes=no])

AC_ARG_WITH(libnids_libraries,
    AS_HELP_STRING([--with-libnids-libraries=DIR], [Search for libnids library in DIR. Effective only if --enable-extraflib has been previously specified]),
	[with_libnids_libraries="$withval"],[with_libnids_libraries=no])

#If any of the above libnids options has been specified,
#check that --enable-extraflib has been specified too
if test x$extraflib != xtrue; then
	if test "$with_libnids_includes" != "no"; then
		AC_MSG_ERROR(Please use --with-libnids-includes only in conjunction with --with-extraflib. You don't need to configure libnids if you are not going to use it)
	fi
	if test "$with_libnids_libraries" != "no"; then
		AC_MSG_ERROR(Please use --with-libnids-libraries only in conjunction with --with-extraflib. You don't need configure libnids if you are not going to use it)
	fi
fi

if test x$extraflib = xtrue; then
echo " with extraflib, looking for nids... "
	save_CPPFLAGS=$CPPFLAGS
	save_LDFLAGS=$LDFLAGS 
	save_LIBS=$LIBS

	if test "$with_libnids_includes" != "no"; then
		NIDSINC="-I${with_libnids_includes}"
		CPPFLAGS="${CPPFLAGS} ${NIDSINC}"
	fi

	if test "$with_libnids_libraries" != "no"; then
	   NIDSLIB="-L${with_libnids_libraries} "
	fi

	NIDSLIB="${NIDSLIB} -lnids"
	LDFLAGS="${LDFLAGS} ${NIDSLIB}"

	echo ${LDFLAGS}
	echo ${CPPFLAGS}

	# Verify that we have the headers
	NIDS_H=""
	AC_CHECK_HEADER(nids.h,, NIDS_H="no")
	if test "$NIDS_H" = "no"; then
	  echo "   ERROR!  Libnids header not found, go get it "
	  exit 1
	fi

	# Verify that we have the library
	#if test -f "${with_libnids_libraries}/libnids.a"; then
	#	echo "libnids.a exists"
	#else
	#	echo "libnids.a does not exist"
	#fi

	NIDS_L=""
	AC_CHECK_LIB(nids, nids_pcap_handler, ,NIDS_L="no")
	if test "$NIDS_L" = "no"; then
		echo "    ERROR!  Libnids library not found or < 1.21 , go get it"
		exit 1
	fi

	CPPFLAGS=$save_CPPFLAGS
	LDFLAGS=$save_LDFLAGS 
	LIBS=$save_LIBS

	AC_SUBST(NIDSINC)
	AC_SUBST(NIDSLIB)

fi
echo " ----------------------END LIBNIDS---------------------------------"
#end of libnids ...

#
# libpcre  (only for --enable-extraflib) - based on Snort's configure.in
#
AC_ARG_WITH(libpcre_includes,
	AS_HELP_STRING([--with-libpcre-includes=DIR], [Search for libpcre headers in DIR. Effective only if --enable-extraflib has been previously specified]),
	[with_libpcre_includes="$withval"],[with_libpcre_includes=no])

AC_ARG_WITH(libpcre_libraries,
	AS_HELP_STRING([--with-libpcre-libraries=DIR], [Search for libpcre library in DIR. Effective only if --enable-extraflib has been previously specified]),
	[with_libpcre_libraries="$withval"],[with_libpcre_libraries=no])

wants_pcre=false
if test x$extraflib = xtrue || test x$anonflib = xtrue; then
	wants_pcre=true
fi

# if any of the above pcre options has been specified,
#check that --enable-extraflib or --enable-anonflib has been specified too
if test x$wants_pcre != xtrue; then
	if test "$with_libpcre_includes" != "no"; then
		AC_MSG_ERROR(Please use --with-libpcre-includes only in conjunction with --with-extraflib or --with-anonflib. You don't need to configure libpcre if you are not going to use any of them)
	fi
	if test "$with_libpcre_libraries" != "no"; then
		AC_MSG_ERROR(Please use --with-libpcre-libraries only in conjunction with --with-extraflib or --with-anonflib. You don't need configure libpcre if you are not going to use any of them)
	fi
fi

# check for libpcre only if --enable-extraflib or --enable-anonflib has been specified
if test x$wants_pcre = xtrue; then

	save_CPPFLAGS=$CPPFLAGS
	save_LDFLAGS=$LDFLAGS 
	save_LIBS=$LIBS

	if test "$with_libpcre_includes" != "no"; then
		PCREINC="-I${with_libpcre_includes}"
		CPPFLAGS="${CPPFLAGS} ${PCREINC}"
	else	
		PCREINC="`pcre-config --cflags`"
		CPPFLAGS="${CPPFLAGS} ${PCREINC}"
	fi

	if test "$with_libpcre_libraries" != "no"; then
	   PCRELIB="-L${with_libpcre_libraries} -lpcre"
	   LDFLAGS="${LDFLAGS} ${PCRELIB}"
	else
		# this should give something like "-L/usr/lib -lpcre"
		PCRELIB="`pcre-config --libs`"
		LDFLAGS="${LDFLAGS} ${PCRELIB}"
	fi

	# PCRE configuration (required)
	# Verify that we have the headers
	PCRE_H=""
	AC_CHECK_HEADER(pcre.h,, PCRE_H="no")
	if test "$PCRE_H" = "no"; then
	  echo
	  echo "   ERROR!  Libpcre header not found, go get it from"
	  echo "   http://www.pcre.org"
	  exit 1
	fi

	# Verify that we have the library
	PCRE_L=""
	AC_CHECK_LIB(pcre, pcre_compile, ,PCRE_L="no")
	if test "$PCRE_L" = "no"; then
		echo 
		echo "    ERROR!  Libpcre library not found, go get it from"
		echo "    http://www.pcre.org"
		echo
		exit 1
	fi

	CPPFLAGS=$save_CPPFLAGS
	LDFLAGS=$save_LDFLAGS 
	LIBS=$save_LIBS

	AC_SUBST(PCREINC)
	AC_SUBST(PCRELIB)

fi # test x$extraflib = xtrue

#
# SSL - based on stunnel's configure.ac (only for --enable-ssl)
#
checkssldir() { :
    if test -f "$1/include/openssl/ssl.h"
    then AC_DEFINE([HAVE_OPENSSL], 1, [whether we are using openssl])
        ssldir="$1"
        return 0
    fi
    if test -f "$1/include/ssl.h"
    then ssldir="$1"
        return 0
    fi
    return 1
}

if test x$ssl = xtrue; then
	AC_MSG_CHECKING([for SSL directory]);
fi
AC_ARG_WITH(ssl, AS_HELP_STRING([--with-ssl=DIR], [Location of installed SSL libraries/include files]),
	[
		# Check the specified localtion only
		if test x$ssl = xtrue; then
			checkssldir "$withval"
		else
			AC_MSG_ERROR(Please use --with-ssl only in conjunction with --enable-dimapi and --enable-ssl. You don't need to configure SSL if you are not going to use DiMAPI with secure sockets.)
		fi
	],
	[
		if test x$ssl = xtrue; then
			# Search default localtions of SSL library
			for maindir in /usr/local /usr/lib /usr/pkg /usr /var/ssl /opt; do
				for dir in $maindir $maindir/openssl $maindir/ssl; do
					checkssldir $dir && break 2
				done
			done
		fi
	]
)
if test x$ssl = xtrue; then
	if test -z "$ssldir"; then
		AC_MSG_RESULT([Not found])
		echo
		echo "Couldn't find your SSL library installation dir"
		echo "Use --with-ssl option to fix this problem"
		echo
		exit 1
	fi
	AC_MSG_RESULT([$ssldir])
	SSLINC="-I$ssldir/include"
	SSLLIB="-L$ssldir/lib -lssl"
	AC_SUBST(SSLINC)
	AC_SUBST(SSLLIB)
fi

#
# misc libs
#
save_LIBS=$LIBS
AC_CHECK_LIB(m, floor,,)
AC_CHECK_LIB(rt, sem_wait,,)
LIBS=$save_LIBS


# these checks will be good only if the special cases are handled
# appropriately in the code

# Checks for typedefs, structures, and compiler characteristics.
#AC_C_CONST
#AC_C_INLINE
#AC_TYPE_SIZE_T
#AC_HEADER_TIME
#AC_TYPE_UID_T
#AC_C_VOLATILE
# Checks for library functions
#AC_FUNC_ALLOCA
#AC_FUNC_ERROR_AT_LINE
#AC_FUNC_MALLOC
#AC_FUNC_MEMCMP
#AC_FUNC_REALLOC
#AC_FUNC_SELECT_ARGTYPES
#AC_TYPE_SIGNAL
#AC_FUNC_STRNLEN
#AC_FUNC_VPRINTF
#AC_CHECK_FUNCS([bzero getcwd gethostbyname gettimeofday memmove memset select socket strchr strdup strerror strrchr strstr strtol])

CONFDIR=`eval echo $sysconfdir/mapi`
AC_DEFINE_DIR(CONFDIR, CONFDIR, [configuration directory])
DATADIR=`eval echo $datadir/mapi`
AC_DEFINE_DIR(DATADIR, DATADIR, [directory for drivers and function librarues])

CFLAGS=-g
if test "$GCC" = "yes"; then
	CFLAGS="$CFLAGS -W -Wall -Wcast-align -Wpointer-arith"
fi

AC_MSG_NOTICE([generating files --------------------------------------------])
AC_CONFIG_FILES([
	Makefile
	src/Makefile
	src/common/Makefile
	src/lib/Makefile
	src/drivers/Makefile
	src/stdflib/Makefile
	src/trackflib/Makefile
	src/rulerflib/Makefile
	src/ipfixflib/Makefile
	src/anonflib/Makefile
	src/dagflib/Makefile
	src/dagflib/bpfcompiler/Makefile
	src/dagflib/bpfcompiler/pcap/Makefile
	src/napatechflib/Makefile
	src/extraflib/Makefile
	applications/Makefile
	applications/appmon/Makefile
	applications/mapidump/Makefile
	doc/Makefile
	etc/Makefile
	etc/mapi.conf
])
AC_OUTPUT

echo ""
echo "Configuration:"
echo "Install path:              ${prefix}"
echo "Binaries:                  ${prefix}/sbin"
echo "libmapi:                   ${prefix}/lib"
echo "Headers:                   ${prefix}/include"
echo "Configuration files:       ${CONFDIR}"
echo "drivers/functions/misc:    ${DATADIR}"
echo "MAPI function libraries:   ${MAPI_FUNC_LIBS}"
echo "mapid user group:          ${MAPI_GROUP}"
if test x$dimapi = xtrue; then
echo "option:                    DiMAPI"
fi
if test x$ssl = xtrue; then
echo "option:                    SSL"
fi
if test x$dag = xtrue; then
echo "option:                    support for DAG cards"
fi
if test x$napatech = xtrue; then
echo "option:                    support for Napatech NT cards"
fi
if test x$napatech_x = xtrue; then
echo "option:                    support for Napatech X cards"
fi
if test x$authentication = xtrue; then
echo "option:                    authentication on"
fi
if test x$reconnect = xtrue; then
echo "option:                    RECONNECTION"
fi
