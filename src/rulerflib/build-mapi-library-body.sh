
#--- Start of $Id: build-mapi-library-body.sh,v 1.7 2006/10/26 06:54:34 reeuwijk Exp $ ---
RULERFLAGS="-T mapi.ct"
RULERTEMPLATE=mapi-launcher.ct
VERBOSE=0
EXECUTE=1
MAPI=0

WORKDIR=
OUTPUTFILE=
INPUTFILE=
JUNK=
MAPI_LIB=
MAPI_INCLUDE=

function showusage()
{
    cat << EOF
Usage: $0 [options] <source-file>
Files with the extension '.rl' are first compiled to a .c file with ruler -M.'

Files with the extension '.c' are compiled to a dynamic library module with the same
name as the input, but with extension '.so'.

Options are:
--dir <dir>     Run the compiler in the given working directory.
--dryrun        Only show the needed commands, do not execute them. Implies --verbose.
--help          Show this help text.
--mapi          Compile a MAPI library instead of a Ruler module.
--ruler <path>  Use the given executable as Ruler compiler.
--verbose       Show the compilation steps.
-d <dir>        Run the compiler in the given working directory.
-help           Show this help text.
-h              Show this help text.
-n              Only show the needed commands, do not execute them. Implies --verbose.
-o <file>       Write the output (the library module) to the given file.
-v              Show the compilation steps.
EOF
}

trap "exit 1" 1 2 3 15

while [ $# -gt 0 ]; do
    case "$1" in
        -n|--dryrun)
            EXECUTE=0
            shift
            ;;

        -v|--verbose)
            VERBOSE=1
            shift
            ;;

        --mapi)
            MAPI=1
            shift
            ;;

        -h|-help|--help)
            showusage
            exit 0
            ;;

        -d|--dir)
            WORKDIR=$2
            shift
            shift
            ;;

        --ruler)
            RULER=$2
            shift
            shift
            ;;

        -o)
            OUTPUTFILE=$2
            shift
            shift
            ;;

        *)
            if [ X$INPUTFILE = X ]; then
                INPUTFILE=$1
            else
                echo "More than one source file given: '$INPUTFILE' and '$1'"
                echo "Giving up"
                echo
                showusage
                exit 1
            fi
            shift
            ;;
    esac
done

if [ X$OUTPUTFILE = X ]; then
    case "$INPUTFILE" in
        *.rl)
            OUTPUTFILE=`basename $INPUTFILE .rl`.so
            ;;

        *.c)
            OUTPUTFILE=`basename $INPUTFILE .c`.so
            ;;

        *)
            echo "Don't know what to do with source file '$INPUTFILE'. Giving up."
            exit 1
    esac
fi

if [ $MAPI = 1 ]; then
    if [ X$INPUTFILE = X ]; then
        echo "No source file given; giving up"
        echo
        showusage
        exit 1
    fi


    if [ ! "$MAPI_DIR" ]; then
        echo "Environment variable MAPI_DIR must be set, and point to the"
        echo "Installation directory of MAPI (i.e. PREFIX in mapi/Makefile.in)."
        echo "Giving up."
        exit 2
    fi
    PROBEFILE=$MAPI_DIR/include/mapi/mapi.h
    if [ ! -e $PROBEFILE ]; then
        echo "File '$PROBEFILE' does not exist."
        echo "Have you installed MAPI? Have you set environment variable"
        echo "MAPI_DIR correctly? It is set to '$MAPI_DIR'."
        echo "Giving up."
        exit 2
    fi
    if [ ! "$MAPI_SRC_DIR" ]; then
        echo "Environment variable MAPI_SRC_DIR must be set. Giving up."
        exit 2
    fi
    MAPI_INCLUDE="-I$MAPI_DIR/include/mapi -I$MAPI_SRC_DIR"
    MAPI_LIB=$MAPI_DIR/lib/mapi/mapi.so
fi

if [ X$WORKDIR != X ]; then
    cd $WORKDIR
    if [ $VERBOSE = 1 ]; then
        echo "Changed working directory to '`pwd`'"
    fi
fi

case "$INPUTFILE" in
    *.rl)
        if [ $VERBOSE = 1 ]; then
            echo "Compiling Ruler source file $INPUTFILE"
        fi
        if [ X$WORKDIR != X ]; then
            OUT=$WORKDIR/src.c
        else
            OUT=src.c
        fi
        CMD="$RULER $RULERFLAGS -T$RULERTEMPLATE $INPUTFILE -o $OUT"
        if [ $VERBOSE = 1 ]; then
            echo "Working directory: `pwd`"
            echo "[$CMD]"
        fi
        if [ $EXECUTE = 1 ]; then
            $CMD
        fi
        INPUTFILE=$OUT
        JUNK="$JUNK $OUT"
        ;;

    *.c)
        ;;

    *)
        echo "Don't know what to do with source file '$INPUTFILE'. Giving up."
        exit 1
esac

if [ $VERBOSE = 1 ]; then
    echo "Building MAPI function $1"
fi
CMD="$CC -o $OUTPUTFILE $MAPI_INCLUDE $CFLAGS $MAPI_LIB $INPUTFILE"
if [ $VERBOSE = 1 ]; then
    echo "Working directory: `pwd`"
    echo "[$CMD]"
fi
if [ $EXECUTE = 1 ]; then
    $CMD
fi
if [ ${#JUNK} != 0 ]; then
    CMD="rm -f $JUNK"
    if [ $VERBOSE = 1 ]; then
        echo "Working directory: `pwd`"
        echo "[$CMD]"
    fi
    if [ $EXECUTE = 1 ]; then
        $CMD
    fi
fi
