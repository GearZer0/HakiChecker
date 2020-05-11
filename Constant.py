
from datetime import datetime

# String constants
NONE = "N/A"
UNKNOWN = "Unknown"
SS_SAVED = "Screenshot saved"
SS_FAILED = "Failed to save screenshot"
EX_SERVER = ": {} is having problems. Please try again later."
EX_UNAUTH = ": Unauthorized. Please check API key"

# Modes
IP_MODE = 'ip'
URL_MODE = 'url'
FILE_MODE = 'file'
HASH_MODE = 'hash'

# Directory constants
FG_KEYS = "fraudguard_keys.txt"
CONFIG = "config.txt"

# SOME CONFIG, related to input output file
SAVE_IP = "ip_{}.csv".format(datetime.now().strftime("%Y-%m-%d_%H%M"))  # save result for ip here
SAVE_URL = "url_{}.csv".format(datetime.now().strftime("%Y-%m-%d_%H%M"))  # save result for url here
SAVE_FILE = "file_{}.csv".format(datetime.now().strftime("%Y-%m-%d_%H%M"))  # save result for files here
SAVE_HASH = "hash_{}.csv".format(datetime.now().strftime("%Y-%m-%d_%H%M"))  # save result for hash here

# OSINT constants
# [VirusTotal] api / links
VT = 'VirusTotal'
VT_URL = 'https://www.virustotal.com/api/v3/urls'
VT_FILE = 'https://www.virustotal.com/api/v3/files'
VT_FILE_BIG = 'https://www.virustotal.com/api/v3/files/upload_url'
VT_IP = 'https://www.virustotal.com/api/v3/ip_addresses/{}'
VT_SS = 'https://www.virustotal.com/gui/{identifier}/{target}/detection'

# [AbuseIPDB] api / links
ABIP = 'AbusedIP'
ABIP_IP = 'https://api.abuseipdb.com/api/v2/check'
ABIP_SS = 'https://www.abuseipdb.com/check/{}'

# [IBM]
IBM = 'IBM'
IBM_IP = 'https://api.xforce.ibmcloud.com/ipr/{}'
IBM_URL = 'https://api.xforce.ibmcloud.com/url/{}'
IBM_SS = 'https://exchange.xforce.ibmcloud.com/search/{}'

# [Fraud Guard]
FG = 'FraudGuard'
FG_IP = 'https://api.fraudguard.io/ip/{}'
FG_SS = 'https://fraudguard.io/?ip={}'

# [URLScan]
URLSCAN = 'URLScan'
URLSCAN_URL = 'https://urlscan.io/api/v1/scan/'
URLSCAN_SS_ORIGIN = 'https://urlscan.io/screenshots/'
URLSCAN_SS = 'https://urlscan.io/result/{}'

#[Google Safe]
GOOGLE = 'GoogleSafeBrowsing'
GOOGLE_URL = 'https://safebrowsing.googleapis.com/v4/threatMatches:find?key='
GOOGLE_SS = 'https://transparencyreport.google.com/safe-browsing/search?url={}&hl=en'

# [Auth0]
AUTH0 = 'Auth0'
AUTH0_IP = 'https://signals.api.auth0.com/v2.0/ip/{}'
AUTH0_SS = 'https://auth0.com/signals/ip/{}-report'

# [PhishTank]
PHISH = 'PhishTank'
PHISH_URL = 'https://checkurl.phishtank.com/checkurl/'
PHISH_SS = 'https://www.phishtank.com/'

# [Cisco Talos]
CISCO = 'CiscoTalos'
CISCO_SS = 'https://talosintelligence.com/reputation_center/lookup?search='

# [Hybrid Analysis]
HYBRID = 'HybridAnalysis'
HYBRID_IP = 'https://www.hybrid-analysis.com/api/v2/quick-scan/url-for-analysis'

# [Alien Vault]
AV = "AlienVault"
AV_IPV4 = 'https://otx.alienvault.com/api/v1/indicators/IPv4/{}/general'
AV_IPV6 = 'https://otx.alienvault.com/api/v1/indicators/IPv6/{}/reputation'
AV_URL = 'https://otx.alienvault.com/api/v1/indicators/submit_url'
AV_URL_GET = 'https://otx.alienvault.com/api/v1/indicators/url/{url}'
AV_FILE = 'https://otx.alienvault.com/api/v1/indicators/submit_file'
AV_FIEL_GET = 'https://otx.alienvault.com/api/v1/indicators/file/{file_hash}/{section}'