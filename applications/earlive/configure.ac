#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_INIT(ear_monitor, 0.2, vpappas@ics.forth.gr)
AM_CONFIG_HEADER([config.h])
AC_CONFIG_SRCDIR([src/hex.c])
AM_INIT_AUTOMAKE(foreign no-dependencies no-installinfo)

# Checks for programs.
AC_PROG_AWK
if test $AWK != gawk; then
	AC_MSG_ERROR("gnu awk (gawk) is needed")
fi
AC_PROG_CC
AC_PROG_LIBTOOL

# Options
# checks if mapi is going to be used
AC_MSG_CHECKING(if mapi is enabled)
AC_ARG_ENABLE(mapi, 
	AC_HELP_STRING([--disable-mapi], [disable mapi]),
	enable_mapi="${enableval}", 
	enable_mapi="yes")

if test x$enable_mapi = xyes; then
	AC_MSG_RESULT(yes)
	# libmapi
	AC_CHECK_LIB([mapi], [mapi_create_flow], , 
		AC_MSG_ERROR("mapi not found.You can install it or run ./configure --disable-mapi"))

else
	AC_DEFINE([NO_MAPI], [1], [To use mapi or not to use])
	AC_MSG_RESULT(no)
	AC_CHECK_HEADER([nids.h])
	AC_CHECK_LIB([nids], [nids_run], , AC_MSG_ERROR("libnids is not installed"))
fi

# checks if stride is going to be used
AC_MSG_CHECKING(if stride is enabled)
AC_ARG_ENABLE(stride, 
	AC_HELP_STRING([--enable-stride], [enable stride]),
	enable_stride="${enableval}", 
	enable_stride="no")

AM_CONDITIONAL([BINARY_STRIDE], [test x$enable_stride = xyes])

if test x$enable_stride = xyes; then
	AC_MSG_RESULT(yes)
else
	AC_MSG_RESULT(no)
fi

# web server root dir
AC_ARG_WITH(www_dir, 
	AC_HELP_STRING([--with-www_dir], [web server's root directory]),
	www_dir="${withval}",
	www_dir="default")

if test x$www_dir = xdefault; then
	www_dir="/var/www/earlive/"
fi

AC_DEFINE_UNQUOTED([EARLIVE_DIR], ["${www_dir}"], [EarLive's Directory])
AC_SUBST(WWW_DIR, [$www_dir])

# Checks for libraries.
# libpcap
AC_CHECK_LIB([pcap], [pcap_open_live], , AC_MSG_ERROR("pcap not found"))


# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([arpa/inet.h fcntl.h netinet/in.h stdlib.h string.h sys/socket.h sys/time.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_C_INLINE
AC_HEADER_TIME
AC_TYPE_UINT32_T

# Checks for library functions.
AC_FUNC_ERROR_AT_LINE
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_TYPE_SIGNAL
AC_CHECK_FUNCS([bzero gettimeofday memset strdup strtol])

AC_CONFIG_FILES([Makefile
				 www_files/Makefile
				 etc/Makefile
				 scripts/Makefile
				 src/Makefile
                 src/ear/Makefile
                 src/stride/Makefile])
AC_OUTPUT
