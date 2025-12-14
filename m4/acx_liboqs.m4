AC_DEFUN([ACX_LIBOQS],[
	WITH_LIBOQS=
	AC_ARG_WITH(liboqs,
		AS_HELP_STRING([--with-liboqs=PATH],[Specify prefix of path of liboqs]),
		[
			LIBOQS_PATH="$withval"
			WITH_LIBOQS=1
		],
		[
			LIBOQS_PATH="/usr/local"
		])

	if test -n "${PKG_CONFIG}" && test -z "${WITH_LIBOQS}"; then
		PKG_CHECK_MODULES([LIBOQS], [liboqs >= $1.$2.$3], [
			AC_MSG_RESULT([checking for liboqs via pkg-config ... yes])
		],[
			AC_MSG_ERROR([Cannot find liboqs via pkg-config])
		])
	else
		if test -f "$LIBOQS_PATH/include/oqs/oqs.h"; then
			LIBOQS_CFLAGS="-I$LIBOQS_PATH/include"
			LIBOQS_LIBS="-L$LIBOQS_PATH/lib -loqs"
		else
			AC_MSG_ERROR([Cannot find liboqs includes at $LIBOQS_PATH/include/oqs/oqs.h])
		fi

		AC_SUBST(LIBOQS_CFLAGS)
		AC_SUBST(LIBOQS_LIBS)
	fi

	AC_MSG_CHECKING(what are the liboqs includes)
	AC_MSG_RESULT($LIBOQS_CFLAGS)

	AC_MSG_CHECKING(what are the liboqs libs)
	AC_MSG_RESULT($LIBOQS_LIBS)

	tmp_CPPFLAGS=$CPPFLAGS
	tmp_LIBS=$LIBS

	CPPFLAGS="$CPPFLAGS $LIBOQS_CFLAGS"
	LIBS="$LIBS $LIBOQS_LIBS -lcrypto"

	AC_LANG_PUSH([C])
	AC_LINK_IFELSE(
		[AC_LANG_PROGRAM(
			[#include <oqs/oqs.h>],
			[OQS_randombytes(NULL, 0);])],
		[AC_MSG_RESULT([checking for liboqs >= v$1.$2.$3 ... yes])],
		[AC_MSG_RESULT([checking for liboqs >= v$1.$2.$3 ... no])
		 AC_MSG_ERROR([Missing the correct version of the liboqs library])]
	)
	AC_LANG_POP([C])

	# liboqs needs libcrypto
	LIBOQS_LIBS="$LIBOQS_LIBS -lcrypto"
	AC_SUBST(LIBOQS_LIBS)

	CPPFLAGS=$tmp_CPPFLAGS
	LIBS=$tmp_LIBS
])
