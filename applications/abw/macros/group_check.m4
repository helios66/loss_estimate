dnl -*-Autoconf-*-
dnl --------------------------------------------------------
dnl Check for GROUP presence
dnl --------------------------------------------------------

dnl GROUP_CHECK([GROUP])
AC_DEFUN([GROUP_CHECK],[

	if test -n "$1" ; then
		GROUP=$1
	else
		GROUP="abw"
	fi

	AC_MSG_CHECKING(checking for group $GROUP)
	grep -q "^$GROUP:" /etc/group
	if test $? -eq 0 ; then
		CREATE_GROUP=0
		AC_MSG_RESULT(yes)
	else
		CREATE_GROUP=1
		AC_MSG_RESULT(no)
	fi

	AC_SUBST(CREATE_GROUP)
	AC_SUBST(GROUP)
])
