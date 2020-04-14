# SOC_ReputationChecker
<pre>

This script check the reputation of IP addresses, Url, Hashes or Files from mutiple OSINT.

<b>Take screenshot of Url</b> (urlscan.io)
Whenever a url requested, screenshot of the url will be automatically taken and placed in images folder. 
Default delay is set at 30s, -d will overwrite the default delay.

<b>Mutiple file scan</b> (Virustotal) - Maximum 32MB
Upload mutiple file to Virustotal. Put each directory of the file into .txt

<b>Hash equivalent</b> (Virustotal) 

<b>IP Address</b> (All-in-One)
IBM, AbusedIPDB, FraudGuard, Auth0

<b>url</b> (All-in-One)
Virustotal, IBM, urlscan.io, GoogleSafeBrowsing

<b>Command</b>
-ip list.txt		Choose IP Address as Parameter 
-url list.txt		Choose url as Parameter 
-hash list.txt		Choose hash as Parameter 
-file list.txt		Choose file as Parameter
-d x			set delay between search

<b>Examples</b>
python SOC_ReputationChecker.py -ip list.txt 
python SOC_ReputationChecker.py -ip -d 2 list.txt 
python SOC_ReputationChecker.py -url -d 30 list.txt 
python SOC_ReputationChecker.py -hash list.txt 
python SOC_ReputationChecker.py -file -d 90 list.txt 

<b>Requirements</b>
IBM : https://exchange.xforce.ibmcloud.com/
	- Login to IBM and get API KEY and API PASSWORD
	- input API KEY and API PASSWORD into API KEYS section in the script
	- Public API : 5,000 API requests per month
	
Fraudguard.io : https://fraudguard.io</b>
	- Login to fraudguard.io and get API KEY USERNAME and PASSWORD
	- input API KEY USERNAME and PASSWORD into fraudguard.txt. USERNAME:PASSWORD
	- (optional) more than one API KEY into each line, it will rotate between API KEY
	- Public API : 1,000 API requests per month

AbuseIPDB : https://www.abuseipdb.com/
	- Login to AbuseIPDB and get API KEY 
	- input API KEY into API KEYS section in the script
	- Public API : 1,000 API requests per day

Auth0 : https://auth0.com/signals/ip
 	- Login to Auth0 and get API KEY 
	- input API KEY and API PASSWORD into API KEYS section in the script
	- Public API : 4,000 API requests per day. 40,000 hits per day, each API request consume 10 hits

Virustotal : https://www.virustotal.com/gui/home
 	- Login to Virustotal and get API KEY 
	- input API KEY into API KEYS section in the script
	- Public API : 4 requests per minute. Set at least 15s delay i.e -d 15
	- For file upload, set at least 60s.

urlscan.io : https://urlscan.io/
 	- Login to urlscan.io and get API KEY 
	- input API KEY into API KEYS section in the script
	- urlscan.io takes time to process, set delay to at least 30s

<b>Known issue</b>
- IBM returns N/A if url is too long. This is IBM API issue.
- urlscan.io returns N/A if the delay is not long enough (Please put at least 30 seconds delay i.e -d 30)
- Virustotal file upload returns N/A if the delay is not long enough (Please put at least 60 seconds delay i.e -d 60)
- Virustotal file upload returns N/A despite the delay is long enough at first upload, 
  sometimes it takes more time for the server to process your file

<b>Experiment</b>
- Virustotal : inital upload maybe just need few seconds, since the process take so long to return result, it gives N/A when delay is not enough.
	Since file data will be stored once it is completed. To test inital upload delay 5s, then enter same command again 

</pre>