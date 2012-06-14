TORBlock
========

TORBlock is a BASH script to automatically download the list of TOR exit-nodes and add them to your IPTables ruleset.

Requirements
----------------
- iptables
- curl
- cut
- grep

This script uses hosts advertised on TOR's public exit-node list in order to extract IP addresses and roll out the rules.

@TODO
---------
- Implement in BSD's IPF
