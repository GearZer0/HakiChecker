# HakiChecker

This tool check the reputation of IP addresses, Urls, Hashes or Files from multiple OSINT. Everything All-in-One!

## OSINT used
##### IP Address Reputation Check
* IBM, VirusTotal, AbusedIPDB, FraudGuard, Auth0

##### URL Reputation Check
* Virustotal, IBM, urlscan.io, GoogleSafeBrowsing, PhishTank

    For urlscan.io, whenever a url requested, screenshot of the url will be automatically taken and placed in folder. 

##### Multiple file Scan
* Virustotal

    File can be of any size. Any file larger than 32 MB will take a longer time (around a few minutes) and anything that goes over 200 MB may 
    affect the performance.
    
##### Hash Reputation and Hash equivalent Hash Check
* Virustotal

    Accepts Hash type of Sha1, Sha256 and MD5 and returns equivalent hash with reputation.

## Safe or block?
The logic to calculate if the url/ip to display "To block" at the **Action** column of the output 
is "if anything that does not belong to their default score if no IOC is found", will be flagged 
as "To block"

Below are the Safe score (their default score if no IOC is found)
```
  IP
    - IBM : 1 out of 10
    - Virustotal: 0 out of x
    - AbuseIPDB : 0 out of 100
    - FraudGuard : 1 out of 5
    - Auth0 : 0

   URL
    - Virustotal : 0 out of x
    - IBM : 1 out of 10
    - GoogleSafeBrowsing : Safe
    - Phish Tank : False
    - urlscan.io : 0 out of 100 (Only available for screenshot mode)
```
Anything other than the above will be flagged as "To block"

## Requirements
#### 1. Installations
* Python 3
* Git (optional)

#### 2. Clone Repo or Download
After installation of Git, type this into Git Bash. Note that this is just one of the many ways to clone a repository.
```
git clone https://github.com/GearZer0/HakiChecker.git
```

#### 3. Get API KEYS

##### [IBM:](https://exchange.xforce.ibmcloud.com/)
 IBM X Force Provides an API to get the Reputation details of IPAddress, Urls and Hashes. This script only uses IBM to 
 check for IPs and URLs.  Public API supports **5,000 API requests per month**.
1.  Login to IBM and get API KEY and API PASSWORD
2.  Open up `config.txt` and under `[IBM]`, append API KEY after `ibm_apikey = ` and append API PASS after `ibm_apipass = `
 
	
##### [Fraudguard.io:](https://fraudguard.io)
FraudGuard provides API to check IP reputation. Its public API supports **1000 requests per month**.
1. Login to fraudguard.io and get API KEY USERNAME and PASSWORD
2. Input API KEY USERNAME and PASSWORD into `fraudguard.txt` in this format `USERNAME:PASSWORD`
3. (optional) more than one API KEY into each line, it will rotate between API KEY

Score Definition:
```
1 = No Risk
2 = Spam or Website Abuse (excessive scraping, resource linking or undesired site automation)
3 = Open Public Proxy
4 = Tor Node
5 = Honeypot, Malware, Botnet or DDoS Attack
```
##### [AbuseIPDB:](https://www.abuseipdb.com/)
AbuseIPDB provides reputation check on IP Addresses. Its public API supports **1000 API requests per day**.
1. Login to AbuseIPDB and get API KEY 
2. Open up `config.txt` and under `[AbuseIPDB]`, append API KEY after `abip_apikey = `
3. Public API : 1,000 API requests per day

##### [Auth0:](https://auth0.com/signals/ip)
Auth0 checks reputation of IP Addresses. Public API supports **4000 API requests per day** or 40,000 hits per day, where 
each API consumes 10 hits.
1. Login to Auth0 and get API KEY 
2. Open up `config.txt` and under `[Auth0]`, append API KEY after `auth0_apikey = `

Score Definition:
```
0: Auth0 Signals is neutral about the IP address given. It means the service cannot find the IP address 
   in any given individual service and cannot classify the IP as risky.
-1: Auth0 Signals has detected the IP address in one of the checks. This is the lowest level of risk of 
    an IP address.
-2: Auth0 Signals has detected the IP address in two checks. This is the medium level of risk of 
    an IP address.
-3: Auth0 Signals has detected the IP address in all the checks. This is the highest risk level 
    of an IP address.
```

##### [Virustotal:](https://www.virustotal.com/gui/home)
Virus Total is one of the most comprehensive OSINT. It can check for IPs, URLs, Hashes and files. Public API supports 
**4 requests per minute**.
1. Login to Virustotal and get API KEY 
2. Open up `config.txt` and under `[Virus Total]`, append API KEY after `vt_apikey = `

##### [urlscan.io:](https://urlscan.io/)
URLscan.io can check for URLs and take screenshots. It generally takes a long time is only enabled for screenshot mode.
1. Login to urlscan.io and get API KEY 
2. Open up `config.txt` and under `[URLscan]`, append API KEY after `urlscan_apikey = `
	
##### [GoogleSafeBrowsing:](https://developers.google.com/safe-browsing)
Google Safe is used to lookup URLs and any URLs found is considered unsafe.
1. To generate API Keys, login to your gmail account and follow this [guide](https://www.synology.com/en-us/knowledgebase/SRM/tutorial/Safe_Access/How_to_generate_Google_Safe_Browsing_API_keys)
2. Open up `config.txt` and under `[Google Safe]`, append API KEY after `google_apikey = `
	
Threat Definition:
```
THREAT_TYPE_UNSPECIFIED 	  Unknown.
MALWARE 			  Malware threat type.
SOCIAL_ENGINEERING 		  Social engineering threat type.
UNWANTED_SOFTWARE 		  Unwanted software threat type.
POTENTIALLY_HARMFUL_APPLICATION   Potentially harmful application threat type.
```
##### [PhishTank:](https://www.phishtank.com/api_info.php)
Phish Tank is used to check for phishing site. 
1. Login to Phish Tank and register for a new application to get API KEY 
2. Open up `config.txt` and under `[Phish Tank]`, append API KEY after `phish_apikey = `
3. `phish_user` should be a name describing the application use or it can be left blank. Its API supports **2000 
requests per 5 minute**.

## Commands Available
To run the script, there are a few commands available. 
```
-ip list.txt		Choose IP Address as Parameter 
-url list.txt		Choose url as Parameter 
-hash list.txt		Choose hash as Parameter 
-file list.txt		Choose file as Parameter
-sip xx.xx.xx.xx	check single IP address
-surl xxxxxx		check single url
-shash xxxxxxxx		check single hash
-ss                 sceenshot mode
```
These are some examples of the commands that can be types in cmd.
```
IP
- python HakiChecker.py -ip list.txt 		check IP address
- python HakiChecker.py -sip xx.xx.xx.xx	check single IP address

URL
- python HakiChecker.py -url list.txt  	    check url without screenshot (URLscan.io not used)
- python HakiChecker.py -url list.txt -ss   check url with screenshot mode (URLscan.io)
- python HakiChecker.py -surl xxx		    check single url without screenshot (URLscan.io not used)
- python HakiChecker.py -surl xxx -ss	    check single url with screenshot mode (URLscan.io)

HASH
- python HakiChecker.py -hash list.txt   	check hash or equivalent Hash
- python HakiChecker.py -shash xxxxxx		check single hash

FILE
- python HakiChecker.py -file list.txt      check file
```

### Known issue
- IBM returns N/A if url is too long. This is IBM API issue.
- Virustotal file upload returns N/A despite the delay is long enough at first upload, 
  sometimes it takes more time for the server to process your file

### FAQ
Q : Why file upload requires long delay? 

A : Virustotal takes some time to finish the file upload process (the bigger the file the longer the delay)

Q : Why screenshot requires long delay

A : urlscan.io takes some time to to finish the process

### Experiment
- Virustotal : 	initial upload maybe just need few seconds, since the process take so long to return result, 
		it gives N/A when delay is not enough. Since file data will be stored once it is completed. 
		To test initial upload delay 5s, let the VS finish the computation then enter same command 
		again after 2 minutes 

### Source
https://auth0.com/signals/docs/#get-full-ip-address-reputation-info
https://faq.fraudguard.io/threat-levels
https://developers.google.com/safe-browsing/v4/lookup-api
https://developers.google.com/safe-browsing/v4/reference/rest/v4/ThreatType
