# HakiChecker

This tool check the reputation of IP addresses, Urls, Hashes or Files from multiple OSINT. Everything All-in-One! 
It supports **screenshot mode** where screenshot of the OSINT results are taken automatically.

## OSINT used
##### IP Address Reputation Check
* IBM, VirusTotal, AbusedIPDB, FraudGuard, Auth0, CiscoTalos

    CiscoTalos is only checked when Screenshot mode is enabled.
##### URL Reputation Check
* Virustotal, IBM, GoogleSafeBrowsing, PhishTank, URLscan.io, CiscoTalos

    Both CiscoTalos and URLscan.io will only be checked when screenshot mode is enabled. 
    URLScan.io also provides a screenshot of the target URL aside from its screenshot.

##### Multiple file Scan
* Virustotal

    File can be of any size. Any file larger than 32 MB will take a longer time (around a few minutes) and 
    anything that goes over 200 MB may affect the performance.
    
##### Hash Reputation and Hash equivalent Hash Check
* Virustotal

    Accepts Hash type of Sha1, Sha256 and MD5 and returns equivalent hash with reputation.

## Safe or block?
The url/ip should display "Safe" at the **Action** column of the output when it is their 
default score (no IOC is found) or when the results are N/A ( which can mean unsuccessful or unknown). Everything 
else will be flagged as "To block"

Below are the Safe score (their default score if no IOC is found) 
```
  IP
    - IBM : 1 out of 10 | N/A (if unknown)                           
    - Virustotal: 0 out of x
    - AbuseIPDB : 0 out of 100
    - FraudGuard : 1 out of 5
    - Auth0 : 0
    - CiscoTalos: Neutral | Favorable | Trusted | N/A (if unknown)  (Only for screenshot mode)

   URL
    - Virustotal : 0 out of x
    - IBM : 1 out of 10 | N/A (if unknown)  
    - GoogleSafeBrowsing : Safe
    - Phish Tank : False
    - Urlscan.io : 0 out of 100                                     (Only for screenshot mode)
    - CiscoTalos: Neutral | Favorable | Trusted | N/A (if unknown)  (Only for screenshot mode)
```
Anything other than the above (except N/A) will be flagged as "To block"

## Results
All the results will be saved in the `Results` folder (Not applicable for single search mode).

```
Syntax:  Results/<type of check>_<year>_<month>_<date>_<24hr time>
Example: Results/ip_2020-05-06_0958.csv
```
When screenshot mode is enabled (`-ss`), all the images will be saved in `Images` folder as a `.png` file.
Screenshot will be saved for both normal mode and single check mode.
```
Syntax:  Images/<type of check>/<ip address/urldomain/hash/filename>_<OSINT>.png
Example: Images/ip/8.8.8.8_IBM.png
         Images/url/something.com_URLScan.png
         Images/hash/xxxxxxxxxxxxxxx_VirusTotal.png
         Images/file/nameoffile_VirusTotal.png   ** example from input C:/Users/xxxx/Downloads/sample.pdf
```

## Requirements
#### 1. Basic Installations
* Python 3 + pip
* Git (optional)


#### 2. Clone Repo or Download
After installation of Git, type this into Git Bash. Note that this is just one of the many ways to clone a repository.
```
git clone https://github.com/GearZer0/HakiChecker.git
```

#### 3. Setup Screenshot Mode
Screenshot mode and CiscoTalos uses selenium which requires a driver.
1. Check Google Chrome version from `chrome settings > about Chrome`
2. Download chrome driver with correct version from [here](https://sites.google.com/a/chromium.org/chromedriver/downloads) 
3. Unzip the downloaded zip file
4. Open up `config.txt` and in the first line, append the directory which contains the driver after `drive = ` . For example: 
    ```console
    drive = C:/Users/xxxx/Downloads/chromedriver.exe
    ```

#### 4. Get API KEYS

##### [IBM:](https://exchange.xforce.ibmcloud.com/)
 IBM X Force Provides an API to get the Reputation details of IPAddress, Urls and Hashes. This script only uses IBM to 
 check for IPs and URLs.  Public API supports **5,000 API requests per month**.
1.  Login to IBM and get API KEY and API PASSWORD
2.  Open up `config.txt` and under `[IBM]`, append API KEY after `ibm_key = ` and append API PASSWORD after `ibm_pass = `
 
	
##### [Fraudguard.io:](https://fraudguard.io)
FraudGuard provides API to check IP reputation. Its public API supports **1000 requests per month**.
1. Login to fraudguard.io and get API KEY USERNAME and PASSWORD
2. Input API KEY USERNAME and PASSWORD into `fraudguard.txt` in this format `USERNAME:PASSWORD`
3. (optional) more than one API KEY into each line, it will rotate between different API KEY if the limit is exceeded

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
2. Open up `config.txt` and under `[AbuseIPDB]`, append API KEY after `abip_key = `

##### [Auth0:](https://auth0.com/signals/ip)
Auth0 checks reputation of IP Addresses. Public API supports **4000 API requests per day** or 40,000 hits per day, where 
each API consumes 10 hits.
1. Login to Auth0 and get API KEY 
2. Open up `config.txt` and under `[Auth0]`, append API KEY after `auth0_key = `

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
2. Open up `config.txt` and under `[Virus Total]`, append API KEY after `vt_key = `

##### [urlscan.io:](https://urlscan.io/)
URLscan.io can check for URLs and take screenshots. It generally takes a long time is only enabled for screenshot mode.
1. Login to urlscan.io and get API KEY 
2. Open up `config.txt` and under `[URLscan]`, append API KEY after `urlscan_key = `
	
##### [GoogleSafeBrowsing:](https://developers.google.com/safe-browsing)
Google Safe is used to lookup URLs and any URLs found is considered unsafe.
1. To generate API Keys, login to your gmail account and follow this 
[guide](https://www.synology.com/en-us/knowledgebase/SRM/tutorial/Safe_Access/How_to_generate_Google_Safe_Browsing_API_keys)
2. Open up `config.txt` and under `[Google Safe]`, append API KEY after `google_key =`
	
Threat Definition:
```
THREAT_TYPE_UNSPECIFIED             Unknown
MALWARE                             Malware threat type
SOCIAL_ENGINEERING                  Social engineering threat type
UNWANTED_SOFTWARE                   Unwanted software threat type
POTENTIALLY_HARMFUL_APPLICATION     Potentially harmful application threat type
```
##### [PhishTank:](https://www.phishtank.com/api_info.php)
Phish Tank is used to check for phishing site. 
1. Login to Phish Tank and register for a new application to get API KEY 
2. Open up `config.txt` and under `[Phish Tank]`, append API KEY after `phish_key = `
3. `phish_user` should be a name describing the application use or it can be left blank. Its API supports **2000 
requests per 5 minute**.

Score Definition:
```
False:          The URL is determined as not a phish or it does not exists in the database
Questionable:   Phishtank is in the process of determining whether the URL which was reported is a phish
Phish:          Phishtank has detected the URL as a phish
```

##### [Cisco Talos:](https://talosintelligence.com/reputation_center)
Cisco Talos checks for IP and URL reputation. It requires Chrome driver which should have been installed earlier when
setting up screenshot mode in **step 3**.

Web Reputation Levels:
```
Trusted:        Displaying behavior that indicates exceptional safety
Favorable:      Displaying behavior that indicates a level of safety
Neutral:        Displaying neither positive or negative behavior. However, has been evaluated.
Questionable:   Displaying behavior that may indicate risk, or could be undesirable
Untrusted:      Displaying behavior that is exceptionally bad, malicious, or undesirable
Unknown:        Not previously evaluated, or lacking features to assert a threat level verdict
```

## Commands Available
To run the script, there are a few commands available. Input can be in the form of csv or text file.
```
-ip list.txt	    Choose IP Address as Parameter 
-url list.txt	    Choose url as Parameter 
-hash list.txt	    Choose hash as Parameter 
-file list.txt	    Choose file as Parameter
-sip xx.xx.xx.xx    check single IP address
-surl xxxxxx        check single url
-shash xxxxxxxx     check single hash
-ss                 sceenshot mode
```
These are some examples of the commands that can be types in cmd.
```
IP
- python HakiChecker.py -ip list.txt            check IP address
- python HakiChecker.py -ip list.txt -ss        check IP address (Screenshot Mode)
- python HakiChecker.py -sip xx.xx.xx.xx        check single IP address
- python HakiChecker.py -sip xx.xx.xx.xx -ss    check single IP address (Screenshot Mode)

URL
- python HakiChecker.py -url list.txt  	        check url
- python HakiChecker.py -url list.txt -ss       check url (Screenshot Mode)
- python HakiChecker.py -surl xxx               check single url
- python HakiChecker.py -surl xxx -ss	        check single url (Screenshot Mode)

HASH
- python HakiChecker.py -hash list.txt          check hash or equivalent Hash
- python HakiChecker.py -hash list.txt -ss      check hash or equivalent Hash (Screenshot Mode)
- python HakiChecker.py -shash xxxxxx           check single hash
- python HakiChecker.py -shash xxxxxx -ss       check single hash (Screenshot Mode)

FILE
- python HakiChecker.py -file list.txt          check file
- python HakiChecker.py -file list.txt -ss      check file (Screenshot Mode)
```

### Known issue
- IBM returns N/A if url is too long. This is IBM API issue.
- When URLscan's API takes longer than 65 seconds, it will return N/A
- When screenshot fails, please check the network connection and retry
(if it is too weak, it may take too long to load which can cause timeout and result in failed screenshot)
- When there is an change in interface for any OSINT, screenshot mode for that OSINT may start to fail because it is 
heavily dependent on the interface (web scraping). When this happens, please let me know so that I can update the code
 to match the interface.
- CiscoTalos says: "Please go to www.cisco..... to check if captcha is required and complete it once". If after doing this,
it still continues to say that, there are 3 solutions. (A) Try using VPN (B) Open up Screenshot.py and change
 `options.add_argument("--headless")` to `# options.add_argument("--headless")` and `timeout = 20` to `timeout = 60`. 
 This will cause chrome browser to open up for each of the OSINT. When CiscoTalos is being checked, you will see that
  a captcha is required. Please complete the captcha in 1 minute and let it load on its own. (C) Ignore Cisco Talos

### FAQ
##### Q : Why file upload requires long delay? 
A : Virustotal takes some time to finish the file upload process (the bigger the file the longer the delay)

##### Q : Why screenshot takes longer time?
A : urlscan.io and the screenshot process akes a while

##### Q: Why does the OSINT returns N/A sometimes?

A: IBM and CiscoTalos will return N/A when the url or ip is classified as **unknown**. 
When an OSINT continuously returns N/A for all the reputation check, it means there was a problem getting the results.
This may be due to a few reasons:
 1. Wrong API key => please check your config.txt  
 2. Exceeded limit for that API => wait or make more api key (depends on different OSINT)
 3. Bugs
 4. OSINT server issue => This is due to their server problem 
 5. Time out for URLscan.io => check network
If this problem persists after retrying, please contact me via email. 

### Source
https://auth0.com/signals/docs/#get-full-ip-address-reputation-info
https://faq.fraudguard.io/threat-levels
https://developers.google.com/safe-browsing/v4/lookup-api
https://developers.google.com/safe-browsing/v4/reference/rest/v4/ThreatType
https://talosintelligence.com/reputation_center/support#faq3
