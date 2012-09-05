dnl -*-Autoconf-*-
dnl --------------------------------------------------------
dnl Check for MAPI presence
dnl --------------------------------------------------------

dnl MAPI_CHECK([MAPI_DIR])
AC_DEFUN([MAPI_CHECK],[
	MAPI_DIRS="$1\
		/usr/local/mapi	\
		"

	CHECKING_MSG="for mapi.h and libmapi.so in "

	for d in $MAPI_DIRS; do
		AC_MSG_CHECKING($CHECKING_MSG $d)
		if test -f $d/include/mapi.h -a -f $d/lib/libmapi.so ; then
			AC_MSG_RESULT(yes)
			MAPI_DIR="$d"
			MAPI_CFLAGS="-I$d/include"
			MAPI_LIBS="$d/lib/libmapi.so"
			break
		else
			AC_MSG_RESULT(no)
		fi
	done

	if test -z "$MAPI_CFLAGS" -o -z "$MAPI_LIBS" ; then
	   echo "***"
	   echo "*** MAPI was not found."
	   echo "***"
	   exit 1
	fi

	AC_SUBST(MAPI_DIR)
	AC_SUBST(MAPI_CFLAGS)
	AC_SUBST(MAPI_LIBS)
])
