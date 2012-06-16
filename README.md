TORBlock
========

TORBlock is a BASH script to automatically download the list of TOR exit-nodes and add them to your IPTables ruleset.

This script uses hosts advertised on TOR's public exit-node lists in order to extract IP addresses and roll out the rules.

TORBlock uses and (configurable) dedicated chain (default = TORBLOCK) in order to ease management and permit chain flushing
on updates.

EXPERIMENTAL
------------------
WARNING! The 'OPT_REDIR' function is under implementation and may not work (sorry for that!)

Requirements
----------------
- iptables
- curl
- grep


@TODO
---------
- Implement in BSD's IPF
