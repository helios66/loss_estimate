# Process this file with autoconf to produce a configure script.

m4_define(package_name, [abw])
m4_define(package_version, [0.1])
m4_define(package_bugs, [ubik@cesnet.cz])

AC_PREREQ(2.59)
AC_INIT([package_name],[package_version],[package_bugs])
AM_INIT_AUTOMAKE(1.8)
AC_CONFIG_HEADERS([config.h])

m4_undefine([package_name])
m4_undefine([package_version])
m4_undefine([package_bugs])

AC_PREFIX_DEFAULT(/usr/local/abw)

if test "x$prefix" = "xNONE"; then
   prefix=$ac_default_prefix
fi

test "$localstatedir" = '${prefix}/var' && localstatedir=/var/lib/abw

# --with-mapi
AC_ARG_WITH(
		[mapi],
		AS_HELP_STRING(
				[--with-mapi=DIR],
				[MAPI files in DIR (default /usr/local/mapi)]),
		[ac_mapidir="$withval"],,)

# --with-libdag
AC_ARG_WITH(
		[libdag],
		AS_HELP_STRING(
				[--with-libdag=DIR],
				[DAG files in DIR (default /usr/local/dag)]),
		[DAG_DIR="$withval"],,)

if test "x$DAG_DIR" = "x"; then
   DAG_DIR="/usr/local/dag"
fi

# --with-user
AC_ARG_WITH(
		[user],
		AS_HELP_STRING(
				[--with-user=USER],
				[USER that will own ABW application (default abw)]),
		[ac_user="$withval"],,)

# --with-group
AC_ARG_WITH(
		[group],
		AS_HELP_STRING(
				[--with-group=USER],
				[GROUP that will own ABW application (default abw)]),
		[ac_group="$withval"],,)

######################################################################
# Check for programs.

AC_PROG_CC

# Check for adduser vs. useradd and addgroup vs. groupadd
ADD_USER_GROUP_CHECK()

######################################################################
# Checks for libraries.

# glib
AM_PATH_GLIB_2_0(2.4.0,, AC_MSG_ERROR([
GLIB library of required version was not found. This library is needed
to compile pktloss. Library is available from ftp://ftp.gtk.org/.
]), gthread)

# check for libmapi.a + mapi.h
MAPI_CHECK($ac_mapidir)

######################################################################
# Checks for header files.

# Checks for typedefs, structures, and compiler characteristics.

# Checks for library functions.

# Check for user and group
USER_CHECK($ac_user)
GROUP_CHECK($ac_group)

######################################################################
# Define default configuration values.

#AC_DEFINE_UNQUOTED(HFE_SOURCE_FILE, "$ac_hfe_parser", HFE parser)
#AC_DEFINE_UNQUOTED(LUP_INSTDEF_FILE, "$ac_lup_instructions", LUP instructions definition)

# Set configuration variables
AC_SUBST(ABW_DIR,$prefix)
AC_SUBST(ABW_VAR_DIR,$localstatedir)
AC_SUBST(DAG_DIR)

######################################################################
# Generate output files.

AC_CONFIG_FILES([
Makefile
src/Makefile
scripts/abw.sh
scripts/mapi.sh
scripts/dag.sh
scripts/dag-init.sh
scripts/abw_mapi.sh
scripts/abw_check_rrd.sh
scripts/abw_check_data.sh
scripts/rrd_graph_all.sh
scripts/abw_delete_old_graphs.sh
])

AC_OUTPUT

######################################################################
# Display compiler parameters.

echo ""
echo "USING THIS CONFIGURATION:"
echo "-------------------------"
echo "ABW installation directory: $ABW_DIR"
echo "ABW variable directory: $ABW_VAR_DIR"
echo "MAPI directory: $MAPI_DIR"
echo "DAG directory: $DAG_DIR"

if test $CREATE_USER -gt 0 ; then
	echo "New user $USER will be created as owner of ABW application."
else
	echo "Existing user $USER will be owner of ABW application."
fi
echo "If you do not like it, use --with-user=USER to specify another user."

if test $CREATE_GROUP -gt 0 ; then
	echo "New group $GROUP will be created as owner of ABW application."
else
	echo "Existing group $GROUP will be owner of ABW application."
fi
echo "If you do not like it, use --with-group=GROUP to specify another group."
echo ""
