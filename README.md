# HakiChecker
<pre>

This tool check the reputation of IP addresses, Urls, Hashes or Files from multiple OSINT. Everything All-in-One!

<b>IP Address</b>
IBM, AbusedIPDB, FraudGuard, Auth0

<b>url</b>
Virustotal, IBM, urlscan.io, GoogleSafeBrowsing

<b>Take screenshot of Url</b> (urlscan.io)
Whenever a url requested, screenshot of the url will be automatically taken and placed in folder. 

<b>Multiple file scan</b> (Virustotal) - Maximum 32MB
Upload multiple file to Virustotal. Put each directory of the file into .txt

<b>Hash reputation and Hash equivalent Hash</b> (Virustotal) 

<b>Command</b>
-ip list.txt		Choose IP Address as Parameter 
-url list.txt		Choose url as Parameter 
-hash list.txt		Choose hash as Parameter 
-file list.txt		Choose file as Parameter
-d x			set delay between search

<b>Examples</b>
python HakiChecker.py -ip list.txt 		check IP address with no delay
python HakiChecker.py -url  list.txt -d 30	check url with 30 seconds delay (screenshot mode) 
python HakiChecker.py -url list.txt -d 2 	check url with 2 seconds delay (no screenshot mode)
python HakiChecker.py -hash list.txt 		check hash or equivalent Hash
python HakiChecker.py -file list.txt -d 90      check file with 90 seconds delay

<b>Requirements</b>

Python 3

IBM : https://exchange.xforce.ibmcloud.com/
	- Login to IBM and get API KEY and API PASSWORD
	- input API KEY and API PASSWORD into API KEYS section in the script. APIKEY:APIPASSWORD
	- Public API : 5,000 API requests per month
	
Fraudguard.io : https://fraudguard.io</b>
	- Login to fraudguard.io and get API KEY USERNAME and PASSWORD
	- input API KEY USERNAME and PASSWORD into fraudguard.txt. USERNAME:PASSWORD
	- (optional) more than one API KEY into each line, it will rotate between API KEY
	- Public API : 1,000 API requests per month

	Score Definition
	1 = No Risk
	2 = Spam or Website Abuse (excessive scraping, resource linking or undesired site automation)
	3 = Open Public Proxy
	4 = Tor Node
	5 = Honeypot, Malware, Botnet or DDoS Attack

AbuseIPDB : https://www.abuseipdb.com/
	- Login to AbuseIPDB and get API KEY 
	- input API KEY into API KEYS section in the script
	- Public API : 1,000 API requests per day

Auth0 : https://auth0.com/signals/ip
 	- Login to Auth0 and get API KEY 
	- input API KEY and API PASSWORD into API KEYS section in the script
	- Public API : 4,000 API requests per day. 40,000 hits per day, each API request consume 10 hits

	Score Definition
	0: Auth0 Signals is neutral about the IP address given. It means the service cannot find the IP address 
	   in any given individual service and cannot classify the IP as risky.
	-1: Auth0 Signals has detected the IP address in one of the checks. This is the lowest level of risk of 
	    an IP address.
	-2: Auth0 Signals has detected the IP address in two checks. This is the medium level of risk of 
	    an IP address.
	-3: Auth0 Signals has detected the IP address in all the checks. This is the highest risk level 
	    of an IP address.


Virustotal : https://www.virustotal.com/gui/home
 	- Login to Virustotal and get API KEY 
	- input API KEY into API KEYS section in the script
	- Public API : 4 requests per minute. Set at least 15s delay i.e -d 15
	- For file upload, set at least 60s.

urlscan.io : https://urlscan.io/
 	- Login to urlscan.io and get API KEY 
	- input API KEY into API KEYS section in the script
	- urlscan.io takes time to process, set delay to at least 30s

GoogleSafeBrowsing : https://developers.google.com/safe-browsing
	- Login to your Gmail account and follow the guide below 

	Threat Definition
	THREAT_TYPE_UNSPECIFIED 	  Unknown.
	MALWARE 			  Malware threat type.
	SOCIAL_ENGINEERING 		  Social engineering threat type.
	UNWANTED_SOFTWARE 		  Unwanted software threat type.
	POTENTIALLY_HARMFUL_APPLICATION   Potentially harmful application threat type.

https://www.synology.com/en-us/knowledgebase/SRM/tutorial/Safe_Access/How_to_generate_Google_Safe_Browsing_API_keys

<b>Known issue</b>
- IBM returns N/A if url is too long. This is IBM API issue.
- urlscan.io returns N/A if the delay is not long enough (Please put at least 30 seconds delay i.e -d 30)
- Virustotal file upload returns N/A if the delay is not long enough (Please put at least 60 seconds delay i.e -d 60)
- Virustotal file upload returns N/A despite the delay is long enough at first upload, 
  sometimes it takes more time for the server to process your file

<b>Experiment</b>
- Virustotal : 	initial upload maybe just need few seconds, since the process take so long to return result, 
		it gives N/A when delay is not enough. Since file data will be stored once it is completed. 
		To test initial upload delay 5s, let it finish then enter same command again after 2 minutes 

<b>FAQ</b>
Q : Why file upload requires long delay? 
A : Virustotal takes some time to to finish file upload process (the bigger the file the longer the delay)

Q : Why screenshot requires long delay
A : urlscan.io takes some time to to finish the process

<b>Source</b>
https://auth0.com/signals/docs/#get-full-ip-address-reputation-info
https://faq.fraudguard.io/threat-levels
https://developers.google.com/safe-browsing/v4/lookup-api
https://developers.google.com/safe-browsing/v4/reference/rest/v4/ThreatType
</pre>
