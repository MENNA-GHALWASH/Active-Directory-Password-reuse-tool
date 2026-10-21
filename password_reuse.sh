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
                echo "Error: --target requires an IP address" >&2
                exit 1
            fi
            TARGET="$2"
            shift 2
            ;;
        --krbtgt)
            if [[ $# -lt 2 ]]; then
                echo "Error: --krbtgt requires true or false" >&2
                exit 1
            fi
            case "$2" in
                true|false)
                    KRBTGT="$2"
                    ;;
                *)
                    echo "Error: value must be true or false" >&2
                    exit 1
                    ;;
            esac
            shift 2
            ;;
        --psswd)
            if [[ $# -lt 2 || -z "$2" ]]; then
                echo "Error: you must provide valid active directory domain credentials" >&2
                exit 1
            fi
            PSSWD="$2"
            shift 2
            ;;
        --domain)
            if [[ $# -lt 2 || -z "$2" ]]; then
                echo "please provide the domain name" >&2
                exit 1
            fi
            DOMAIN_NAME="$2"
            shift 2
            ;;
        --username)
            if [[ $# -lt 2 || -z "$2" ]]; then
                echo "please provide the domain admin username" >&2
                exit 1
            fi
            UNAME="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1" >&2
            exit 1
            ;;
    esac
done

echo "KRBTGT setting: $KRBTGT" >&2

# Extract NT hashes from the domain controller.
#
# Samba AD DC path (default):
#   Impacket's -just-dc (DRSUAPI) does NOT work against a Samba DC.
#   It returns "DRSR SessionError: code: 0x0 - ERROR_SUCCESS" and no
#   hashes. Extract via `pdbedit -Lw` inside the DC container instead.
#   The awk reshapes `user:uid:lm:nt:[U]:LCT:` into
#   `DOMAIN\user:rid:lm:nt:::` (what parse_hashes.py expects),
#   skips machine accounts ($-suffixed) and accounts with no NT hash.
#
# Windows AD DC path — replace the raw=$(...) block below with:
#   raw=$(impacket-secretsdump "$DOMAIN_NAME/$UNAME:$PSSWD@$TARGET" -just-dc 2>&1)

raw=$(docker exec samba-dc pdbedit -Lw 2>/dev/null | \
      awk -F: -v domain="$DOMAIN_NAME" '
          NF>=4 && $1 !~ /\$$/ && $4 != "" && $4 !~ /^X+$/ {
              printf "%s\\%s:%s:AAD3B435B51404EEAAD3B435B51404EE:%s:::\n", domain, $1, $2, $4
          }
      ')

# Defensive filter: keep only lines shaped like DOMAIN\user:rid:lm:nt:::
hashes=$(printf '%s\n' "$raw" | grep -E '^[^:]+:[0-9]+:[0-9a-fA-F]+:[0-9a-fA-F]+:')

if [ -z "$hashes" ]; then
    echo "[!] No hashes extracted. Raw extraction output follows:" >&2
    printf '%s\n' "$raw" >&2
    exit 2
fi

if [ "$KRBTGT" = "false" ]; then
    echo "[+] Filtering out krbtgt" >&2
    hashes=$(printf '%s\n' "$hashes" | grep -v -i "krbtgt")
fi

printf '%s\n' "$hashes"
