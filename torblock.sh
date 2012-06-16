#!/bin/bash

# Options Bitmap @DO NOT EDIT
OPT_LOG=1
OPT_BLOCK=2
OPT_REDIRECT=4

####
# Script configuration
###

# Exit node url must retrieve a list with
# one IP by line
EXIT_NODE_URL="https://www.dan.me.uk/torlist/"
#EXIT_NODE_URL="http://10.1.1.114"

# IPTables Chain Name
CHAIN_NAME="TORBLOCK"

# Logging options
LOG_LEVEL=7 # RFC5424 Severity levels: 0 = Emergency, 1 = Alert, 2 = Critical, 3 = Error,  4 = Warning, 5 = Notice, 6 = Informational, 7 = Debug
LOG_LIMIT_AMT=5 # Limit Amount
LOG_LIMIT_BURST=7 # Limit Burst

# Add TORBLOCK hosts to
# INPUT, OUTPUT or FORWARD
ADD_OUTPUT_RULES=0 # 0 = False, 1 = True
ADD_INPUT_RULES=1 # 0 = False, 1 = True
ADD_FORWARD_RULES=1 # 0 = False, 1 = True

# Action to perform.
# Sum up the options needed.
# Available: OPT_LOG, OPT_BLOCK (-j DROP)
#            and OPT_REDIRECT (NAT)
ACTIONS=$OPT_LOG+$OPT_REDIRECT # WARNING: Cannot DROP and NAT

# Redirect to IP (Only if OPT_REDIRECT is set)
REDIRECT_IP="10.1.1.112"

####
# Script variables and constants
# DO NOT EDIT BELOW THIS LINE
###

# Options Bitmap 
OPT_LOG=1
OPT_BLOCK=2
OPT_REDIRECT=4

# Bins
BIN_CURL=$(which curl)
BIN_IPTABLES=$(which iptables)
BIN_IPTABLES_SAVE=$(which iptables-save)

# Holders
TOR_IPS=""
ACTION_SET=$(($ACTIONS))
IPTABLES_SAVE_OUT=$($BIN_IPTABLES_SAVE)

check() {
    # Make sure only root can run our script
    if [[ $EUID -ne 0 ]]; then
        echo "This script must be run as root" 1>&2
        exit 1
    fi

    # OPT_BLOCK and OPT_REDIRECT cannot be set both
    if [ $(is_action $OPT_BLOCK) -eq 1 ] && [ $(is_action $OPT_REDIRECT) -eq 1 ]; then
        echo "Cannot Drop (OPT_BLOCK) and Redirect (OPT_REDIRECT) request at the same time" 1>&2
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

    _TOR_HOSTS_ADDED=0

    # Check if $CHAIN_NAME chain exists
    if [ $(has_rule ":$CHAIN_NAME") -eq 0 ]; then
        echo "Chain $CHAIN_NAME absent, creating..."
        $BIN_IPTABLES -N $CHAIN_NAME
    fi

    # Check if chain is added to input and output and forward
    ## INPUT
    if [ $(has_rule "-A INPUT -j $CHAIN_NAME") -eq 0 -a $ADD_INPUT_RULES -eq 1 ]; then
        echo "Adding chain $CHAIN_NAME rule to INPUT top (-I)"
        $BIN_IPTABLES -I INPUT -j $CHAIN_NAME
    fi

    ## OUTPUT
    if [ $(has_rule "-A OUTPUT -j $CHAIN_NAME") -eq 0 -a $ADD_OUTPUT_RULES -eq 1 ]; then
        echo "Adding chain $CHAIN_NAME rule to OUTPUT top (-I)"
        $BIN_IPTABLES -I OUTPUT -j $CHAIN_NAME > /dev/null 2>&1
    fi

    # FORWARD
    if [ $(is_action $OPT_REDIRECT) -eq 1 ]; then
        # NAT REDIR Chain
        if [ $(has_rule ":${CHAIN_NAME}_REDIRECT") -eq 0 ]; then
            $BIN_IPTABLES -t nat -N ${CHAIN_NAME}_REDIRECT 2>&1
        fi

        # Postrouting & Masquerade
        if [ $(has_rule "-A POSTROUTING -j MASQUERADE") -eq 0 ]; then
            echo "Adding NAT Masquerade rule"
            $BIN_IPTABLES -t nat -A POSTROUTING -j MASQUERADE 2>&1
        fi

        # Add default postroute to REDIR chain 
        if [ $(has_rule "-A PREROUTING -j ${CHAIN_NAME}_REDIRECT") -eq 0 ]; then
            $BIN_IPTABLES -t nat -A PREROUTING -j ${CHAIN_NAME}_REDIRECT 2>&1
        fi

        if [ $(has_rule "-A FORWARD -j $CHAIN_NAME") -eq 0 -a $ADD_FORWARD_RULES -eq 1 ]; then
            echo "Adding chain $CHAIN_NAME rule to FORWARD top (-I)"
            $BIN_IPTABLES -I FORWARD -j $CHAIN_NAME > /dev/null 2>&1
        fi


    fi

	# Flushing rules
	echo "Flushing rules from $CHAIN_NAME chain"
	$BIN_IPTABLES -F $CHAIN_NAME

	# Add rules
	echo "Adding IPs to chain"
    for i in $TOR_IPS; do

        if [ $(is_ip $i) -eq 1 ]; then
            echo "'$i' is not an valid ip. Skipping" 1>&2
            continue
        fi

        # LOG
        if [ $(is_action $OPT_LOG) -eq 1 ]; then
            $BIN_IPTABLES -A $CHAIN_NAME -s $i -j LOG -m limit --limit ${LOG_LIMIT_AMT}/m --limit-burst $LOG_LIMIT_BURST --log-prefix "TORBLOCK: Inbound access: " --log-level $LOG_LEVEL > /dev/null 2>&1 # source LOG
        fi

        # DROP
        if [ $(is_action $OPT_BLOCK) -eq 1 ]; then
            $BIN_IPTABLES -A $CHAIN_NAME -s $i -j DROP > /dev/null 2>&1  # source DROP 
        fi

        # REDIRECT
        if [ $(is_action $OPT_REDIRECT) -eq 1 ] && [ "$REDIRECT_IP" != "" ]; then
            $BIN_IPTABLES -t nat -A ${CHAIN_NAME}_REDIRECT -s $i -j DNAT --to-destination $REDIRECT_IP > /dev/null 2>&1  # source REDIRECT
        fi

        # Add to OUTPUT ?
        if [ $ADD_OUTPUT_RULES -eq 1 ]; then
            # Log
            if [ $(is_action $OPT_LOG) -eq 1 ]; then
                $BIN_IPTABLES -A $CHAIN_NAME -d $i -j LOG -m limit --limit ${LOG_LIMIT_AMT}/m --limit-burst $LOG_LIMIT_BURST --log-prefix "TORBLOCK: Outbound access: " --log-level $LOG_LEVEL > /dev/null 2>&1 # destination LOG
            fi
            # Block
            if [ $(is_action $OPT_LOG) -eq 1 ]; then
                $BIN_IPTABLES -A $CHAIN_NAME -d $i -j DROP > /dev/null 2>&1 # destination DROP
            fi
        fi
        _TOR_HOSTS_ADDED=$(($_TOR_HOSTS_ADDED+1))
        echo "... added $i to $CHAIN_NAME (source/dest)"
    done;

    echo "$_TOR_HOSTS_ADDED TOR Exit-Nodes successfully added to iptables rules"
}

# Auxiliary Functions

has_rule() {

    _RULE=$1


    echo -e "$IPTABLES_SAVE_OUT" | grep -ei "$_RULE" > /dev/null 2>&1
    if [ $? -eq 1 ]; then
        echo 1;
    else
        echo 0;
    fi

}

is_action() {
    VALID=$(($ACTION_SET | $1))
    if [ $VALID -eq $ACTION_SET ]; then
        echo 1;
    else
        echo 0;
    fi
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
    # DEBUGGING PURPOSES ONLY
	iptables -F INPUT
	iptables -F OUTPUT
	iptables -F FORWARD
	iptables -F $CHAIN_NAME
	iptables -X $CHAIN_NAME
    iptables -t nat -F ${CHAIN_NAME}_REDIRECT
    iptables -t nat -X ${CHAIN_NAME}_REDIRECT
    iptables -t nat -F PREROUTING
    iptables -t nat -F POSTROUTING
}

# Main function

main() {

    #clear_rules #DEBUGGING ONLY! WILL WIPE OUT ALL IPTABLES RULES
    check
    download_list
    add_rules

}

main
