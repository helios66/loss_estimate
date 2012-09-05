AC_PREREQ([2.59])
AC_INIT([netload], [0.1], [mikepo@ics.forth.gr])
AC_CONFIG_SRCDIR(netload.c)
AC_CONFIG_HEADER([config.h])
AM_INIT_AUTOMAKE(foreign no-dependencies)

# Checks for programs.
AC_PROG_CC
if test "$GCC" = "yes"; then
	CFLAGS="$CFLAGS -Wall -Wextra -Wshadow -Wcast-align -Wpointer-arith"
fi
AC_PROG_INSTALL

# Checks for libraries.
AC_CHECK_LIB(mapi, mapi_create_flow,, AC_MSG_ERROR([libmapi not found]))
AC_CHECK_LIB(ncurses, initscr,, AC_MSG_ERROR([libncurses not found]))

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([stdlib.h string.h unistd.h])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
