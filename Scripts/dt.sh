#/bin/bash
#
# ktwo@ktwo.ca
#
# Format a JSON web request for any binary
#
# v.2 moved typedef parameter as part of query string to support wildcards etc..
#
# PDBGUID: (F4 12 A8 DD 28 AC 69 42 AB 80 73 D8 42 38 01 A4)
# becomes {DDA812F4-AC28-4269-AB80-73D8423801A4}
#  
LLVMREADOBJ=`command -v llvm-readobj-4.0`
CURL=`command -v curl`
# A POSIX variable
OPTIND=1
# Initialize our own variables:
output_file=""
verbose=0
input_file=""
ADDRESS=0
BASEVA=0
XSCAN="" 
RERE=""
typedef=""

function show_help() {
    echo "$0 is called with an input file -i [[FILE_TO_PARSE]] and one of [[-t | -A | -X | -r]]"
    echo "-i input_PE_FILE (required)"
    echo "-t _TYPEDUMP (_EPROCESS or _POOL_HEADER etc...)"
    echo "-X Name_*_WildCard"
    echo "-A 0xADDRESS"
    echo "-r (returns relocation data)"
    echo "-h (this help)" 
    echo "-b [[base_va]] (optional)"
    echo "-f output_file (optional)"
    echo "detected arguments were verbose=[[$verbose]], output_file=[['$output_file']]"
    echo "ADDRESS=[[$ADDRESS]] XSCAN=[[$XSCAN]] RERE=[[$RERE]]"
    echo "typedef=[[$typedef]] Leftovers: $@"
    exit
}

while getopts "i:t:h?vf:b:A:X:rb:" opt; do
    case "$opt" in
    h|\?)
        show_help
        exit 0
        ;;
    v)  verbose=1
        ;;
    i)  input_file=$OPTARG
        ;;
    f)  output_file=$OPTARG
        ;;
    t)  typedef=$OPTARG
        ;;
    A)  ADDRESS=$OPTARG
        ;;
    X)  XSCAN=$OPTARG
        ;;
    r)  RERE=1
        ;;
    b)  BASEVA=$OPTARG
    esac
done

shift $((OPTIND-1))

[[ "$1" = "--" ]] && shift

if [[ ! -f $LLVMREADOBJ ]]; then
    echo "Can not find llvm-readobj (attempted $LLVMREADOBJ) exiting"
    return -2
fi
if [[ ! -f $CURL ]]; then
    echo "Can not find curl (attempted $CURL) exiting"
    return -2
fi
if [[ -e $input_file ]]; then
    if (( "$verbose" != 0 )); then
        echo "analyzing file $input_file"
    fi
else
    show_help
    return -1
fi

FILENAME=`basename $input_file`
HEXSIZE=`$LLVMREADOBJ -s $input_file |grep VirtualSize |tail -1|cut -f 2 -d "x"`
HEXADDRESS=`$LLVMREADOBJ -s $input_file |grep VirtualAddress |tail -1|cut -f 2 -d "x"`
THESIZE=`echo "ibase=16; $HEXSIZE"|bc`
THEADDR=`echo "ibase=16; $HEXADDRESS"|bc`
IMAGE_VIRTUALSIZE=`echo "obase=16; ((($THEADDR+$THESIZE+4096)/4096)*4096)"|bc`
TIME_DATE_STAMP=`$LLVMREADOBJ $input_file -coff-debug-directory|grep -i date|tail -1|cut -f 2 -d \(|tr -d \)`

#yeah we call llvm many times oh well ;)
PDBFILENAME=`$LLVMREADOBJ --coff-debug-directory $input_file|grep PDBFileName|cut -f 2 -d :|tr -d " "`
PDBAGE=`$LLVMREADOBJ --coff-debug-directory $input_file|grep PDBAge|cut -f 2 -d :|tr -d " "`
PDBGUIDNFO=`$LLVMREADOBJ -coff-debug-directory $input_file|grep PDBGUID`
GUIDTRIM=`echo $PDBGUIDNFO|cut -d : -f 2|tr -d \( |tr -d \)`
GUIDLEN=`echo $GUIDTRIM|wc -w`
#these need to be reversed 
GUIDX=`(echo -n $GUIDTRIM|cut -d " " -f 4;echo -n $GUIDTRIM|cut -d " " -f 3;echo -n $GUIDTRIM|cut -d " " -f 2;echo -n $GUIDTRIM|cut -d " " -f 1)`
GUID1=`echo $GUIDX|tr -d " "|tr -d '\n'`
GUIDX=`echo -n $GUIDTRIM|cut -d " " -f 6;echo -n $GUIDTRIM|cut -d " " -f 5`
GUID2=`echo $GUIDX|tr -d " "|tr -d '\n'`
GUIDX=`echo -n $GUIDTRIM|cut -d " " -f 8;echo -n $GUIDTRIM|cut -d " " -f 7`
GUID3=`echo $GUIDX|tr -d " "|tr -d '\n'`
#not reversed
GUID4=`echo -n $GUIDTRIM|cut -d " " -f 9-10|tr -d " "`
GUID5=`echo -n $GUIDTRIM|cut -d " " -f 11-|tr -d " "`
FINALGUID="{$GUID1-$GUID2-$GUID3-$GUID4-$GUID5}"

EXTRA_ARGS=""
EXTRA_URL_PARAMS=""

if [[ $output_file -ne "" ]]; then
    EXTRA_ARGS="$EXTRA_ARGS -o $output_file"
fi
if [[ $BASEVA -ne 0 ]]; then
    EXTRA_URL_PARAMS="$EXTRA_URL_PARAMS&baseva=$BASEVA"
fi

function gettypedef() {
    JSON2PDB="https://pdb2json.azurewebsites.net/api/typedef/x?type=$1&guid=$FINALGUID&age=$PDBAGE&PDB=$PDBFILENAME$EXTRA_URL_PARAMS"
    if (( "$verbose" != 0 )); then
        echo "calling server with $CURL $EXTRA_ARGS $JSON2PDB"
    fi

    $CURL $JSON2PDB
}

function getSymNames() {
    JSON2PDB="https://pdb2json.azurewebsites.net/api/SymFromName/x?symname=$1&guid=$FINALGUID&age=$PDBAGE&PDB=$PDBFILENAME$EXTRA_URL_PARAMS"
    if (( "$verbose" != 0 )); then
        echo "calling server with $CURL $EXTRA_ARGS $JSON2PDB"
    fi
    $CURL $JSON2PDB
}

function getSymByAddr() {
    JSON2PDB="https://pdb2json.azurewebsites.net/api/SymFromAddr/x?symaddr=$1&guid=$FINALGUID&age=$PDBAGE&PDB=$PDBFILENAME$EXTRA_URL_PARAMS"
    if (( "$verbose" != 0 )); then
        echo "calling server with $CURL $EXTRA_ARGS $JSON2PDB"
    fi
    $CURL $JSON2PDB
}

function getReRe() {
    JSON2PDB="https://pdb2json.azurewebsites.net/api/Relocs/x?name=$FILENAME&timedate=$TIME_DATE_STAMP&vsize=$IMAGE_VIRTUALSIZE&guid=$FINALGUID&age=$PDBAGE&PDB=$PDBFILENAME$EXTRA_URL_PARAMS"
    if (( "$verbose" != 0 )); then
        echo "calling server with $CURL $EXTRA_ARGS $JSON2PDB"
    fi
    $CURL $JSON2PDB
}

if [[ $typedef != "" ]]; then
    gettypedef $typedef 
elif [[ $XSCAN != "" ]]; then
    getSymNames $XSCAN 
elif [[ $ADDRESS != 0 ]]; then
    getSymByAddr $ADDRESS
elif [[ $RERE -ne "" ]]; then
    getReRe
fi


#echo "Parsed GUID = [[$FINALGUID]] PDBFileName = [[$PDBFILENAME]] PDBAGE = [[$PDBAGE]]"
#echo "Contacting server with $CURL $JSON2PDB?guid=$FINALGUID&age=$PDBAGE&PDB=$PDBFILENAME$EXTRA_URL_PARAMS"

