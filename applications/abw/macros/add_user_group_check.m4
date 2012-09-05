dnl -*-Autoconf-*-
dnl --------------------------------------------------------
dnl Check for adduser vs. useradd and addgroup vs. groupadd
dnl --------------------------------------------------------

dnl ADD_USER_GROUP_CHECK()
AC_DEFUN([ADD_USER_GROUP_CHECK],[

	AC_CHECK_PROG([ADDUSER],[adduser],[adduser])
	AC_CHECK_PROG([ADDUSER],[useradd],[useradd])
	AC_CHECK_PROG([ADDGROUP],[addgroup],[addgroup])
	AC_CHECK_PROG([ADDGROUP],[groupadd],[groupadd])

	if test -z "$ADDUSER" -o -z "$ADDGROUP" ; then
		AC_MSG_RESULT([no])
		AC_MSG_ERROR([Don't know how to create new user or group],[-1]) 
	fi

	if test $ADDUSER = "adduser" ; then
		DEF_GROUP="--ingroup"
		DEF_PASSWD="--disabled-password"
		DEF_HOME="--home"
		DEF_COMMENT="--gecos"
	else
		DEF_GROUP="-g"
		DEF_PASSWD="-p \"*\""
		DEF_HOME="-d"
		DEF_COMMENT="-c"
	fi

	AC_SUBST(DEF_GROUP)
	AC_SUBST(DEF_PASSWD)
	AC_SUBST(DEF_HOME)
	AC_SUBST(DEF_COMMENT)
])
