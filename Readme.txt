Description:
============
Rule2Alert parses snort rules and generates packets on the fly that would alert the IDS. It can either write the packets to a pcap or send the packets directly to the IDS.


Amended:
========
Rule2Alert parses Suricata and/or Snort specific rules and generates packets on the fly that would alert the IDS. 

This development has been concentrated on/for Suricata IDPS on top of(adding to) the existing rule2alert code available here -> http://code.google.com/p/rule2alert/
under GNU GPL v2 (http://www.gnu.org/licenses/old-licenses/gpl-2.0.html).

This develpment works both for Suricata (http://suricata-ids.org/) and Snort(http://www.snort.org/).
Rule2Alert is still in development status. It is an improvement of the original version (alpha) but not all keywords are supported and issues may occur. Please read on carefully.

Assumptions:

	You have python-yaml (apt-get install python-yaml on Ubuntu/Debian like systems) to be able to parse  Suricata's config
	You have Scapy installed on your system
	You have either Suricata or Snort installed on your system 


A list of the fixes and improvements →

Fixed issues:
- dsize:0 – fixed
- dsize:>0 fixed
- no content in rule – fixed (added)
- issue with sid 598 /depth/offset multiple times – fixed
- snort config parser - never worked since introduction of new "ipvar", instead of "var" in the snort config


Rule language keywords support added:
- rawbytes
- tag
- http_uri - allowed 4K more rule/pcap pairs
- flowbits
- threshold:..., count 1 - (only "count 1") added
- “alert http …..”
- “alert ftp …..”
- “alert ip …..”

New features:
- IPv6 support
- Dot1Q (VLAN tag ID) - IEEE 802.1Q (**NOTE** latest community Scapy needed -  http://hg.secdev.org/scapy-com)
- QinQ (double tagged) - IEEE 802.1ad also known as IEEE 802.QinQ (**NOTE** latest community Scapy needed -  http://hg.secdev.org/scapy-com)
- suricata.yaml parser
- logging of separate rules with corresponding pcaps that fail to generate an alert (rule to pcap pair)
- logging of separate rules with corresponding pcaps that do generate an alert (rule to pcap pair)
- choose(or point) to a custom location for suricata.yaml, suricata binary or log directory (see examples below)

---------
EXAMPLE 1 - to make use of the above two (in the rules2alert directory execute):

python r2a.py -C /etc/suricata/suricata.yaml -f rules/emerging-all.rules -w test1.pcap -F -T -e 1.1.1.1 -m 192.168.1.1

- given that you have emerging-all.rules in your rules directory under rules2alert.

---------
EXAMPLE 2 - VLAN ID , Dot1Q:

python r2a.py -C /etc/suricata/suricata.yaml -f /root/Work/Python/rules2alerts/needed/rules/emerging-all.rules -w test1.pcap -F -T -e 1.1.1.1 -m 192.168.1.1 --Dot1Q

---------
EXAMPLE 3 -  QinQ:

python r2a.py -C /etc/suricata/suricata.yaml -f /root/Work/Python/rules2alerts/needed/rules/emerging-all.rules -w test1.pcap -F -T -e 1.1.1.1 -m 192.168.1.1 --QinQ

After whch you will have all the rule/pcap pairs under the rules2alert/output directory.

---------
EXAMPLE 4 - custom location for suricata.yaml, suricata binary , log directory and Dot1Q enabled:

python r2a.py -C /root/Work/tmp/TMP/suricata.yaml -f /root/Work/Python/rules2alerts/needed/rules/emerging-all.rules -w test1.pcap -F -T -e 1.1.1.1 -m 192.168.1.1 -B /usr/bin/suricata -L /root/Work/tmp/TMP/ --Dot1Q

---------
EXAMPLE 5 - IPv6 (-6 option) enabled plus custom location for suricata.yaml, suricata binary , log directory using HOME_NET and EXTERNAL_NET from suricata.yaml:

python r2a.py -C /etc/suricata/suricata.yaml -f /root/Work/Python/rules2alerts/needed/rules/emerging-all.rules -w test1.pcap -F -T  -B /usr/bin/suricata -L /root/Work/tmp/TMP/ -6



You can use the generated output rule/pcap pairs with the RegressionScript -
https://github.com/pevma/RegressionScript

NOTE: Due to lack of not yet implemented support for some rule language keywords not all 'failed' rules/pcap pairs are real failures.






