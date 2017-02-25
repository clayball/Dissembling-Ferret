#!/bin/bash

# Add/delete temporary iptables chain/rule(s).
#
# If you find this useful, awesome! If not, cool, hack it 'til it is or
# drop it like a bad packet.
#
# Command-line arguments:
# - add, del
# - port(s) 1337,7331
# - source 127.0.0.1
# - tcp, udp [tcp]

# Could also check for total number of args, $#
#if [ $# -gt 2 ] && [ "$1" != "cls" ]; then
if ([ ! "$1" ] || [ ! "$2" ] || [ ! "$3" ]) && [ "$1" != "cls" ] ; then
    echo "Usage: $0 add|del port [source] [tcp|udp]"
    echo "       defaults: protocol=tcp"
    exit
fi 


# ######### FUNCTIONS #########
# 
# Two functions might be preferred.
# 1. check for the chain
# 2. if exists then check for the specific rule
# We might want to create multiple rules for this chain.

function check_rule {
    iptables -C $IPCHAIN -p $PROTO --dport $PORT -s $SOURCE -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT 2>nul
    # Return the status code of the command. The code will be 0 if the chain/rule exists
    return $?
}

function check_chain {
    # This produces some unwanted output, adding 2>nul
    iptables -L $IPCHAIN 2>nul
    return $?
}

function delete_session {
    iptables -F $IPCHAIN 2>nul
    if [ $? -eq 0 ]; then
        echo "[*] session rule(s) flushed..."
        iptables -X $IPCHAIN 2>nul
        if [ $? -eq 0 ]; then
            echo "[*] session chain deleted."
        fi
    fi
}


# ######### MAIN SCRIPT #########

ACTION=$1
PORT=$2
SOURCE=$3
# If no protocol provided, default to tcp.
if [ $4 ]; then
    PROTO=$4
else
    PROTO="tcp"
fi

# The new temporary chain is determined from your current TTY.
IPCHAIN=`tty | sed -e 's/\///g'`

echo "[*] ${ACTION} chain ${IPCHAIN}, port ${PORT} ${PROTO} open for ${SOURCE}"

# Each operation should check for the existing chain/rule before performing the
# requested action.
# TODO: add verification checks
if [ "$ACTION" == "add" ]; then
    echo "[*] checking for an existing chain/rule..."
    check_rule
    if [ $? -eq 1 ]; then
        check_chain
        # Returns 0 if the chain exists
        if [ $? -eq 1 ]; then
            echo "[*] chain $IPCHAIN does not exist, adding..."
            iptables -N $IPCHAIN
        else
            echo "[*] chain $IPCHAIN already exists..."
        fi
        echo "[*] rule does not exist, adding..."
        iptables -A $IPCHAIN -p $PROTO --dport $PORT -s $SOURCE -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
        echo "[*] new rule added."
    else
        echo "[-] Chain/rule currently exists. No action taken."
    fi
fi

if [ "$ACTION" == "del" ]; then
    # Check if the chain and rule exists. If so, remove
    echo "[*] checking if chain/rule exists..."
    check_rule
    if [ $? -eq 0 ]; then
        echo "[*] Chain and rule are present, removing..."
        # This only deletes the rule, the chain persists. TODO: remove the chain
        iptables -D $IPCHAIN -p $PROTO --dport $PORT -s $SOURCE -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
    else
        echo "[*] Chain and rule do NOT exist. No action taken."
    fi
fi

if [ "$ACTION" == "cls" ]; then
    echo "[*] Flushing and removing session..."
    delete_session
fi

# EOF
