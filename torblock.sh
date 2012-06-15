#!/bin/bash

# Vars
#EXIT_NODE_URL="http://10.1.1.114"
EXIT_NODE_URL="https://www.dan.me.uk/torlist/"
CHAIN_NAME="TORBLOCK"
LOG_LEVEL=4
LIMIT_AMT=5
LIMIT_BURST=7
ADD_OUTPUT_RULES=0
ADD_INPUT_RULES=1

# Bins
BIN_CURL=$(which curl)
BIN_IPTABLES=$(which iptables)
BIN_IPTABLES_SAVE=$(which iptables-save)

# Holders
TOR_IPS=""

check() {
    # Make sure only root can run our script
    if [[ $EUID -ne 0 ]]; then
        echo "This script must be run as root" 1>&2
        exit 1
    fi
}

download_list() {

    TOR_IPS=$($BIN_CURL -s $EXIT_NODE_URL | sort | uniq)
    if [ "$TOR_IPS" == "" ]; then
        echo "!! Error downloading list from $EXIT_NODE_URL. Exitting.";
        exit 127
    fi

}

add_rules() {

    IPTABLES_SAVE_OUT=$($BIN_IPTABLES_SAVE)

    # Check if $CHAIN_NAME chain exists
    echo -e "$IPTABLES_SAVE_OUT" | grep -e ":$CHAIN_NAME" > /dev/null 2>&1
    if [ $? -eq 1 ]; then
        echo "Chain $CHAIN_NAME absent, creating..."
        $BIN_IPTABLES -N $CHAIN_NAME
    fi

    # Check if chain is added to input and output
    ## INPUT
    echo -e "$IPTABLES_SAVE_OUT" | grep -e "-A INPUT -j $CHAIN_NAME" > /dev/null 2>&1
    if [ $? -eq 1 -a $ADD_INPUT_RULES -eq 1 ]; then
        echo "Adding chain $CHAIN_NAME rule to INPUT top (-I)"
        $BIN_IPTABLES -I INPUT -j $CHAIN_NAME
    fi

    ## OUTPUT
    echo -e "$IPTABLES_SAVE_OUT" | grep -e "-A OUTPUT -j $CHAIN_NAME" > /dev/null 2>&1
    if [ $? -eq 1 -a $ADD_OUTPUT_RULES -eq 1 ]; then
        echo "Adding chain $CHAIN_NAME rule to OUTPUT top (-I)"
        $BIN_IPTABLES -I OUTPUT -j $CHAIN_NAME > /dev/null 2>&1
    fi

	# Flushing rules
	echo "Flushing rules from $CHAIN_NAME chain"
	$BIN_IPTABLES -F $CHAIN_NAME

	# Add rules
	echo "Adding IPs to chain"
    for i in $TOR_IPS; do

        _IS_IP=$(is_ip $i)
        if [ $_IS_IP -eq 1 ]; then
            echo "'$i' is not an valid ip. Skipping"
            continue
        fi

        $BIN_IPTABLES -A $CHAIN_NAME -s $i -j LOG -m limit --limit ${LIMIT_AMT}/m --limit-burst $LIMIT_BURST --log-prefix "TORBLOCK: Inbound access: " --log-level $LOG_LEVEL > /dev/null 2>&1 # source LOG
        $BIN_IPTABLES -A $CHAIN_NAME -s $i -j DROP > /dev/null 2>&1  # source DROP 
        if [ $ADD_OUTPUT_RULES -eq 1 ]; then
            $BIN_IPTABLES -A $CHAIN_NAME -d $i -j LOG -m limit --limit ${LIMIT_AMT}/m --limit-burst $LIMIT_BURST --log-prefix "TORBLOCK: Outbound access: " --log-level $LOG_LEVEL > /dev/null 2>&1 # destination LOG
            $BIN_IPTABLES -A $CHAIN_NAME -d $i -j DROP > /dev/null 2>&1 # destination DROP
        fi
        echo "... added $i to $CHAIN_NAME (source/dest)"
    done;

    echo "TOR Exit-Nodes successfully added to iptables rules"
}

is_ip() {
   if [[ $1 =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
      ret=0
   else
      ret=1
   fi
   echo $ret
}

clear_rules() {
	iptables -F INPUT
	iptables -F OUTPUT
	iptables -F $CHAIN_NAME
	iptables -X $CHAIN_NAME
}

main() {

    #clear_rules
    check
    download_list
    add_rules

}

main
