**Phishing tracker**  

This tool allows you to track phishing campaigns using the tool [dnstwist](https://github.com/elceef/dnstwist), an SQLite
database and [pyMISP](https://pymisp.readthedocs.io/en/latest/modules.html#pymisp)  for storing the potential phishing 
campaigns in a MISP instance.

The tool has 2 parts:
* A Bash file that reads domain names from the domain_list.txt file and checks with Dnstwist the existence of potential 
phishing campaigns supplanting the domain names of the list. In this case, it's also checking MX servers. The output is 
stored in JSON format in the report folder and the domains are stored in the SQLite database for traceability.
* A Python script  with PyMISP for parsing JSON reports by dnstwist and send those domains that aren't stored in the
SQLite database

**Usage**

1. Create two cron jobs:
   1. A cron job for executing tracker.sh
   2. A cron job for executing report2misp.py

For sending the domain name alterations to your MISP instance include the following parameter:

``` bash 
   python report2misp.py --misp
```

If a proxy(-p) is needed:
``` bash 
   python report2misp.py --misp --proxy
```


How the output looks like:

``` bash
[+] Domain monitored: acme.com
		[!] Potential phishing sites: 
		[!] URL: acmea.com
			[+] Technique used: addition
			[+] DNS-ns: ns1.cleverhostdns.com
			[+] DNS-mx: mail.acmea.com
			[+] DNS-a: 173.233.67.102
		[!] URL: acmeb.com
			[+] Technique used: addition
			[+] DNS-ns: nsg1.namebrightdns.com
                        [+] DNS-a: 18.211.9.206
                ........
                .......
[*] Sending alerts to MISP
   [*] Event with ID: 1512 has been successfully stored.

```

**ToDo List**
* Integration with Phishtank