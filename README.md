# wdldumper

WDLDumper > WDigest Lsass Dumper

![alt text](https://i.imgur.com/XeM986l.jpg)

Simple wrapper to dump lsass: enable remote wdigest (impacket wmiexec.py powershell), perform remote lsass dump (impacket wmiexec.py powershell) and lsass parsing (pypykatz + lsassy).

Tested on Win10. Admin creds needed.

Python => 3.6 needed.

Dependencies:

https://github.com/SecureAuthCorp/impacket

https://github.com/skelsec/pypykatz

https://github.com/Hackndo/lsassy
