dnl -*-Autoconf-*-
dnl --------------------------------------------------------
dnl Check for USER presence
dnl --------------------------------------------------------

dnl USER_CHECK([USER])
AC_DEFUN([USER_CHECK],[

	if test -n "$1" ; then
		USER=$1
	else
		USER="abw"
	fi

	AC_MSG_CHECKING(checking for user $USER)
	grep -q "^$USER:" /etc/passwd
	if test $? -eq 0 ; then
		CREATE_USER=0
		AC_MSG_RESULT(yes)
	else
		CREATE_USER=1
		AC_MSG_RESULT(no)
	fi

	AC_SUBST(CREATE_USER)
	AC_SUBST(USER)
])
