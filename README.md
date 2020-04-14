# SOC_ReputationChecker
<pre>

Check the reputation of IP addresses, Url, Hashes or Files from mutiple OSINT.



<b>Take screenshot of Url</b> (urlscan.io)
Whenever a url requestioned, screenshot of the url will be automatically taken and placed in images folder. Default delay is set at 30s, -d will overwrite the default delay.

<b>Mutiple file scan</b> (Virustotal) - Maximum 32MB


<b>Hash equivalent</b> (Virustotal) 

<b>IP Address</b>
IBM, AbusedIPDB, FraudGuard, Auth0

<b>url</b>
Virustotal, IBM, urlscan.io, GoogleSafeBrowsing


<b>Command</b>
-ip list.txt		Choose IP Address as Parameter 
-url list.txt		Choose url as Parameter 
-hash list.txt		Choose hash as Parameter 
-file list.txt		Choose file as Parameter
-d x			set delay between search. example : -url -d 15 list.txt










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




<b>Known issue</b>
IBM returns N/A if url is too long. This is IBM API issue.
urlscan.io returns N/A if the delay is not long enough (Please put at least 30 seconds i.e -d 30)
Virustotal file upload returns N/A if the delay is not long enough (Please put at least 60 seconds i.e -d 60)
Virustotal file upload returns N/A despite the delay is long enough at first upload, sometimes it takes more time for the server to process your file

</pre>