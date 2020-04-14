# SOC_ReputationChecker
<pre>

Check the reputation of IP addresses, Url, Hashes or Files from mutiple OSINT

Take screenshot of Url (urlscan.io)
Mutiple file scan (Virustotal) - Maximum 32MB

IP Address
---------
IBM, AbusedIPDB, FraudGuard, Auth0

url
---
Virustotal, IBM, urlscan.io


-url list.txt		Check
-ip list.txt		test  
-url list.txt		test
-hash list.txt		test
-file list.txt		test











Requirements
<b>https://fraudguard.io</b>



Known issue
-----------
IBM returns N/A if url is too long. This is IBM API issue.
urlscan.io returns N/A if the delay is not long enough (Please put at least 30 seconds i.e -d 30)
Virustotal file upload returns N/A if the delay is not long enough (Please put at least 60 seconds i.e -d 60)
Virustotal file upload returns N/A despite the delay is long enough at first upload, sometimes it takes more time for the server to process your file

</pre>