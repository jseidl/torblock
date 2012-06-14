TORBlock
========

TORBlock is a BASH script to automatically download the list of TOR exit-nodes and add them to your IPTables ruleset.

This script uses hosts advertised on TOR's public exit-node list in order to extract IP addresses and roll out the rules.

TORBlock uses and (configurable) dedicated chain (default = TORBLOCK) in order to ease management and permit chain flushing
on updates.

Requirements
----------------
- iptables
- curl
- cut
- grep


@TODO
---------
- Implement in BSD's IPF
