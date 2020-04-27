# -*- coding: utf8 -*-
import hashlib
import requests
import json
import base64
from urllib.parse import quote
from urllib.parse import urlencode
from time import sleep, time
import csv
from requests.auth import HTTPBasicAuth
import sys
import os
from datetime import datetime

# SOME CONFIG, related to input output file
result_ip_name = "result_ip_{}.csv".format(datetime.now().strftime("%Y-%m-%d_%H%M")) #save result for ip here
result_url_name = "result_url_{}.csv".format(datetime.now().strftime("%Y-%m-%d_%H%M")) #save result for url here
result_file_name = "result_file{}.csv".format(datetime.now().strftime("%Y-%m-%d_%H%M")) #save result for files here
result_hash_name = "result_hash{}.csv".format(datetime.now().strftime("%Y-%m-%d_%H%M")) #save result for hash here

# Specify where the output files should be stored in.
# Currently, it will create a "Results" folder in the current directory and store inside
output_directory = os.getcwd() + "/Results/"

fraudGuardKeys = "fraudguard_keys.txt"
config = "config.txt"
api = {}
hybrid_apikey = "NOT READY"
vt_headers = {'Accept': 'application/json'}
ibm_headers = {"Content-Type": "application/json"}

ip_mode = False
url_mode = False
file_mode = False
hash_mode = False
file_to_read = None
sip_mode = False
surl_mode = False
shash_mode = False
ss_mode = False

#initialise all the api keys and apis from config.txt
def init():
    with open(config) as f:
        for line in f:
            if line != "\n" and not line.startswith('['):
                (key, val) = line.split("=", 1)
                api[key.strip()] = val.strip()

    #Initialise vt_header
    vt_headers['x-apikey'] = api.get("vt_apikey")

    #Initialise ibm_header
    pass_data = api.get("ibm_apikey") + ":" + api.get("ibm_apipass")
    data = base64.b64encode(pass_data.encode())
    final = str(data.decode('utf-8'))
    ibm_headers['Authorization'] = "Basic " + final

    #Create Directory for images
    try:
        os.mkdir("Images")
        os.mkdir("Results")
        #os.mkdir("images_hybrid")
    except:
        pass

# function to save result in csv file
def saveRecord(data, formula):
    if formula == "ip":
        fieldnames = ["Target", "IBM", "VirusTotal", "AbusedIP", "FraudGuard", "Auth0", "Action"]
        with open(output_directory + result_ip_name, mode="a+", encoding="utf-8", newline="") as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
            if os.stat(output_directory + result_ip_name).st_size == 0:
                writer.writeheader()
            malic = "Safe"
            nonzero = 0
            if data[1].startswith("1 out") == False and data[1] != "N/A":
                #malic = "Malicious"
                nonzero += 1
            if data[2].startswith("0 out") == False and data[2] != "N/A":
                #malic = "Malicious"
                nonzero += 1
            if data[3].startswith("0 out") == False and data[3] != "N/A":
                #malic = "Malicious"
                nonzero += 1
            if data[4].startswith("1 out") == False and data[4] != "N/A":
                #malic = "Malicious"
                nonzero += 1
            if data[5] != "0" and data[5] != "N/A":
                #malic = "Malicious"
                nonzero += 1
            if nonzero > 0:
                malic = "To Block"
            writer.writerow({"Target":data[0], "IBM":data[1], "VirusTotal":data[2], "AbusedIP":data[3],
                             "FraudGuard":data[4], "Auth0": data[5], "Action": malic})
    elif formula == "url":
        fieldnames = ["Target", "IBM", "VirusTotal", "URLScan", "GoogleSafeBrowsing", "URLScanUUID", "PhishTank", "Action"]
        with open(output_directory + result_url_name, mode="a+", encoding="utf-8", newline="") as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
            if os.stat(output_directory + result_url_name).st_size == 0:
                writer.writeheader()
            malic = "Safe"
            nonzero = 0
            if data[1].startswith("1 out") == False and data[1] != "N/A":
                #malic = "Malicious"
                nonzero += 1
            if data[2].startswith("0 out") == False and data[2] != "N/A":
                #malic = "Malicious"
                nonzero += 1
            if data[3].startswith("0 out") == False and data[3] != "N/A":
                #malic = "Malicious"
                nonzero += 1
            if data[4].startswith("Safe") == False and data[4] != "N/A":
                #malic = "Malicious"
                nonzero += 1
            if data[6] == True and data[6] != "N/A":
                #malic = "Malicious"
                nonzero += 1
            if nonzero > 0:
                malic = "To Block"
            writer.writerow({"Target":data[0], "IBM":data[1], "VirusTotal":data[2], "URLScan": data[3], "GoogleSafeBrowsing":data[4], "URLScanUUID":data[5], "PhishTank":data[6], "Action" : malic})
    elif formula == "file":
        fieldnames = ["Target", "VirusTotal"]
        with open(output_directory + result_file_name, mode="a+", encoding="utf-8", newline="") as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
            if os.stat(output_directory + result_file_name).st_size == 0:
                writer.writeheader()
            writer.writerow({"Target":data[0], "VirusTotal":data[1]})
    elif formula == "hash":
        fieldnames = ["Target", "MD5", "SHA256", "SHA1", "Score"]
        with open(output_directory + result_hash_name, mode="a+", encoding="utf-8", newline="") as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
            if os.stat(output_directory + result_hash_name).st_size == 0:
                writer.writeheader()
            writer.writerow({"Target":data[0], "MD5":data[1], "SHA256":data[2], "SHA1":data[3], "Score":data[4]})

def getResultVT(res):
    harmless = int(res.json()['data']['attributes']['last_analysis_stats']['harmless'])
    malicious = int(res.json()['data']['attributes']['last_analysis_stats']['malicious'])
    suspicious = int(res.json()['data']['attributes']['last_analysis_stats']['suspicious'])
    undetected = int(res.json()['data']['attributes']['last_analysis_stats']['undetected'])
    rate = str(malicious) + " out of " + str(malicious + harmless + suspicious + undetected)
    return rate

#Get MD5 hash
def md5(fname):
    hash_md5 = hashlib.md5()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

def checkExceptionVT(code):
    if code == 401:
        raise Exception("ERROR: Please verify API KEY!")
    elif code == 429:
        raise Exception("ERROR: Requests Exceeded!")
    elif code != 200:
        raise Exception("")

def virusTotalIP(ip):
    res = requests.get(api.get("vt_ip_api").format(ip), headers=vt_headers)
    checkExceptionVT(res.status_code)
    # available status: harmless, malicious, suspicious, timeout, undetected
    return getResultVT(res)

def virusTotalURL(url):
    # send url to scan
    resp = requests.post(api.get("vt_url_api"), headers=vt_headers, data={'url': url})
    # fetch scan results
    encoded_url = base64.b64encode(url.encode())
    resp = requests.get(
        api.get("vt_url_api").format(encoded_url.decode().replace('=', '')),
        headers=vt_headers)
    checkExceptionVT(resp.status_code)
    # Check if the analysis is finished before returning the results
    # if 'last_analysis_results' key-value pair is empty, then it is not finised
    while not resp.json()['data']['attributes']['last_analysis_results']:
        resp = resp.get(
            api.get("vt_url_api") + '{}'.format(encoded_url.decode().replace('=', '')),
            headers=vt_headers)
        sleep(3)
    #available status: harmless, malicious, suspicious, timeout, undetected
    return getResultVT(resp)

def virusTotalFile(file):
    if not os.path.isfile(file):
        raise Exception('File not found. Please submit a valid file path')
    with open(file, 'rb') as f:
        data = {'file': f.read()}
    #upload file based on size
    file_size = os.path.getsize(file)
    if file_size <= 33554432:
        res = requests.post(api.get("vt_file_api"), headers=vt_headers, files=data)
    else:  # bigger than 32 mb - there may be performance issue as a file gets too big
        res = requests.get(api.get("vt_file_api") + '/upload_url', headers=vt_headers)
        checkExceptionVT(res.status_code)
        upload_url = res.json()['data']
        res = requests.post(upload_url, headers=vt_headers, files=data)
    checkExceptionVT(res.status_code)

    #retrieve analysis
    filehash = str(md5(file))
    return virusTotalHash(filehash)[4]

def virusTotalHash(hash):
    res = requests.get(api.get("vt_file_api") + '/{}'.format(hash), headers=vt_headers)
    checkExceptionVT(res.status_code)
    rate = getResultVT(res)
    # Status: confirmed-timeout, failure, harmless, malicious, suspicious, timeout, type-unsupported, undetected
    md5 = res.json()['data']['attributes']['md5']
    sha256 = res.json()['data']['attributes']['sha256']
    sha1 = res.json()['data']['attributes']['sha1']
    return [hash, md5, sha256, sha1, rate]

# only works for url, no ip support
def abusedIP(ip):
    headers = {
            'Key': api.get("abip_apikey"),
            'Accept': 'application/json',
        }
    params = {
            'ipAddress': ip,
        }
    resp = json.loads(requests.get(api.get("abip_api"), headers=headers, params=params).text)
    rate = str(resp['data']["abuseConfidenceScore"]) + " out of 100"
    return rate

# call to this function when url mode on
def IBM_URL(url):
    resp = json.loads(requests.get(api.get("ibm_url_api") + quote(url), headers=ibm_headers).text)
    rate = str(resp['result']['score']) + " out of 10"
    return rate

# call to this function when ip mode on
def IBM_IP(ip):
    resp = json.loads(requests.get(api.get("ibm_ip_api") + ip, headers=ibm_headers).text)
    rate = str(resp['history'][-1]['score']) + " out of 10"
    return rate

def getFGKey():
    keys = open(fraudGuardKeys, 'r').read().split('\n')
    if keys == "":
        print("Are you sure about FG Keys availability?")
    return keys[0]

def removeOldFGKey(get_key):
    keys = open(fraudGuardKeys, 'r').read().split('\n')
    open(fraudGuardKeys, 'w+').close()
    with open(fraudGuardKeys, 'a+') as fl:
        for i in keys:
            if i != get_key:
                fl.write(i + "\n")
        fl.write(get_key + "\n")

def fraudGuard(ip):
    fg_api = api.get("fg_api") + ip
    get_key = getFGKey()
    username = get_key.split(':')[0]
    password = get_key.split(':')[1]
    resp = requests.get(fg_api, verify=True, auth=HTTPBasicAuth(username, password))
    if resp.status_code == 429:
        print("API limit reached, changing username:password")
        removeOldFGKey(get_key)
        return fraudGuard(ip)
    rate = json.loads(resp.text)['risk_level']
    return rate + " out of 5"

def urlscan(url):
    headers = {"API-Key": api.get("urlscan_apikey")}
    data = {"url": url}
    resp = requests.post(api.get("urlscan_api"), data=data, headers=headers).text
    uuid = json.loads(resp)['uuid']
    nextpage = json.loads(resp)['api']
    result = requests.get(nextpage)
    start = time()
    time_elapsed = 0
    #repeat until url has finished scanning. Max time is 65seconds
    while result.status_code == 404 and time_elapsed < 65:
        sleep(5)
        result = requests.get(nextpage)
        time_elapsed = time() - start
    score = result.json()['verdicts']['overall']['score']
    with open("images/" + uuid + ".png", "wb+") as img_sc:
        try:
            img_sc.write(requests.get(api.get("urlscan_screenshot") + uuid + ".png").content)
        except:
            pass
    return [str(score) + " out of 100", uuid]

def checkExceptionGS(code):
    if code == 403:
        raise Exception("ERROR: Please verify API KEY!")
    elif code == 429:
        raise Exception("ERROR: Requests Exceeded!")
    elif code != 200:
        raise Exception("")

def googleSafe(url):
    data = {
        "client":{"clientId":"ProjectAuto", "clientVersion":"1.5.2"},
        "threatInfo":{
            "threatTypes":["MALWARE", "SOCIAL_ENGINEERING", "THREAT_TYPE_UNSPECIFIED", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes":["WINDOWS"],
            "threatEntryTypes":["URL"],
            "threatEntries":[{"url": url}]}}
    resp = requests.post(api.get("google_api")+api.get("google_apikey"),data=json.dumps(data))
    checkExceptionGS(resp.status_code)
    if "matches" in resp.json().keys():
        return resp.json()["matches"][0]["threatType"]
    else:
        return "Safe"

def auth0(ip):
    headers = {
        "Accept": "application/json",
        "X-Auth-Token":api.get("auth0_apikey")
        }
    resp = requests.get(api.get("auth0_api") + ip,headers=headers).json()
    return str(resp['fullip']['score']).strip()

def hybrid(url):
    data = {
        'scan_type':'all',
        'url':url
        }
    headers = {
        'api-key' : api.get("hybrid_apikey"),
        'user-agent':'Falcon Sandbox'
        }
    resp = requests.post(api.get("hybrid_api"), data=data,headers=headers).json()
    report_id = resp['sha256']
    resp2 = requests.get("https://www.hybrid-analysis.com/api/v2/report/{}/summary".format(report_id),headers=headers).json()
    with open("images_hybrid/" + report_id + ".png", "wb+") as img_sc:
        try:
            img_sc.write(requests.get("https://www.hybrid-analysis.com/api/v2/report/" + report_id + "/screenshots",headers=headers).content)
        except:
            pass
    return resp2['threat_level']

def phishtank(url):
    data = {
        "url": url,
        'format': "json",
        'app_key': api.get("phish_apikey")
        }
    headers = {
        "User-Agent": "phishtank/" + api.get("phish_user")
        }
    resp = requests.post(api.get("phish_api"), headers=headers, data=data)
    return resp.json()['results']['in_database']

if __name__ == "__main__":
    start = time()
    init() #initialisation
    #print(hybrid("https://chase.com.onlinesecuremyaccount.locked.situstaruhanqq820.com/"))

    if len(sys.argv) == 3 or (len(sys.argv) == 4 and sys.argv[3] == "-ss"):
        ok = False
        if sys.argv[1] == "-url":
            url_mode = True
        elif sys.argv[1] == "-ip":
            ip_mode = True
        elif sys.argv[1] == "-file":
            file_mode = True
        elif sys.argv[1] == "-hash":
            hash_mode = True
        elif sys.argv[1] == "-shash":
            shash_mode = True
        elif sys.argv[1] == "-sip":
            sip_mode = True
        elif sys.argv[1] == "-surl":
            surl_mode = True
        file_to_read = sys.argv[2]
        if len(sys.argv) == 4 and sys.argv[3] == "-ss":
            ss_mode = True
        ok = True

        if sip_mode:
            ok = False
            try:
                vt = virusTotalIP(file_to_read)
            except Exception as error:
                if str(error) != "":
                    print(str(error))
                vt = "N/A"
            except:
                vt = "N/A"
            print("VirusTotal: " + vt)
            try:
                abip = abusedIP(file_to_read)
            except:
                abip = "N/A"
            print("Abused IP: " + abip)
            try:
                fg = fraudGuard(file_to_read)
            except:
                fg = "N/A"
            print("FraudGuard: " + fg)
            try:
                ibm_rec = IBM_IP(file_to_read)
            except:
                ibm_rec = "N/A"
            print("IBM: " + ibm_rec)
            try:
                ath0 = auth0(file_to_read)
            except:
                ath0 = "N/A"
            print("Auth0: " + str(ath0))
        elif surl_mode:
            ok = False
            try:
                vt = virusTotalURL(file_to_read)
            except Exception as error:
                if str(error) != "":
                    print(str(error))
                vt = "N/A"
            except:
                vt = "N/A"
            print("VirusTotal: " + vt)
            try:
                ibm_rec = IBM_URL(file_to_read)
            except:
                ibm_rec = "N/A"
            print("IBM: " + ibm_rec)
            try:
                usc = urlscan(file_to_read)
                uscuuid = usc[1]
                usc = usc[0]
            except:
                usc = "N/A"
                uscuuid = "N/A"
            print("URLscan: " + usc)
            try:
                gsb = googleSafe(file_to_read)
            except Exception as error:
                if str(error) != "":
                    print(str(error))
                vt = "N/A"
            except:
                gsb = "N/A"
            print("GoogleSafeBrowsing: " + gsb)
            try:
                pt = phishtank(file_to_read)
            except:
                pt = "N/A"
            print("PhishTank: " + str(pt))
        elif shash_mode:
            ok = False
            hv = virusTotalHash(file_to_read)
            print("md5: " + hv[1])
            print("sha256: " + hv[2])
            print("sha1: " + hv[3])
            print("score: " + hv[4])

        if ok == True:
            file_data = open(file_to_read, 'r').read().split('\n')
            if ip_mode == True:
                for ip in file_data:
                    if ip == "":
                        continue
                    print("---------------------------------------\n" + ip + "\n---------------------------------------")
                    try:
                        vt = virusTotalIP(ip)
                    except Exception as error:
                        if str(error) != "":
                            print(str(error))
                        vt = "N/A"
                    except:
                        vt = "N/A"
                    print("VirusTotal: " + vt)
                    try:
                        abip = abusedIP(ip)
                    except:
                        abip = "N/A"
                    print("Abused IP: " + abip)
                    try:
                        fg = fraudGuard(ip)
                    except:
                        fg = "N/A"
                    print("FraudGuard: " + fg)
                    try:
                        ibm_rec = IBM_IP(ip)
                    except:
                        ibm_rec = "N/A"
                    print("IBM: " + ibm_rec)
                    try:
                        ath0 = auth0(ip)
                    except:
                        ath0 = "N/A"
                    print("Auth0: " + str(ath0))
                    dataset = []
                    dataset.append(ip)
                    dataset.append(ibm_rec)
                    dataset.append(vt)
                    dataset.append(abip)
                    dataset.append(fg)
                    dataset.append(ath0)
                    saveRecord(dataset, "ip")
            elif url_mode == True:
                for url in file_data:
                    if url == "":
                        continue
                    print("---------------------------------------\n" + url + "\n---------------------------------------")
                    try:
                        vt = virusTotalURL(url)
                    except Exception as error:
                        if str(error) != "":
                            print(str(error))
                        vt = "N/A"
                    except:
                        vt = "N/A"
                    print("VirusTotal: " + vt)
                    try:
                        ibm_rec = IBM_URL(url)
                    except:
                        ibm_rec = "N/A"
                    print("IBM: " + ibm_rec)
                    try:
                        usc = urlscan(url)
                        uscuuid = usc[1]
                        usc = usc[0]
                    except:
                        usc = "N/A"
                        uscuuid = "N/A"
                    print("URLscan: " + usc)
                    try:
                        gsb = googleSafe(url)
                    except Exception as error:
                        if str(error) != "":
                            print(str(error))
                        gsb = "N/A"
                    except:
                        gsb = "N/A"
                    print("GoogleSafeBrowsing: " + gsb)
                    try:
                        pt = phishtank(url)
                    except:
                        pt = "N/A"
                    print("PhishTank: " + str(pt))
                    dataset = []
                    dataset.append(url)
                    dataset.append(ibm_rec)
                    dataset.append(vt)
                    dataset.append(usc)
                    dataset.append(gsb)
                    dataset.append(uscuuid)
                    dataset.append(pt)
                    saveRecord(dataset, "url")
            elif file_mode == True:
                for a_file in file_data:
                    startFileTime = time()
                    if a_file == "":
                        continue
                    print("---------------------------------------\nChecking:   " + a_file)
                    try:
                        res = virusTotalFile(a_file)
                    except Exception as error:
                        if str(error) != "":
                            print(str(error))
                        res = "N/A"
                    except:
                        res = "N/A"
                    print("VirusTotal: " + str(res))
                    print("Time Taken: " + str(round(time() - startFileTime, 2)))
                    dataset = []
                    dataset.append(a_file)
                    dataset.append(res)
                    saveRecord(dataset, "file")

            elif hash_mode == True:
                for a_hash in file_data:
                    if a_hash == "":
                        continue
                    print("---------------------------------------\nChecking:   " + a_hash)
                    try:
                        res = virusTotalHash(a_hash)
                        saveRecord(res, "hash")
                        print("VirusTotal: " + str(res[4]))
                    except Exception as error:
                        if str(error) != "":
                            print(str(error))
                        print("VirusTotal: N/A")
                        res = []
                    except:
                        res = []
                        print("VirusTotal: N/A")
            print("---------------------------------------\nTotal Time Elapsed: " + str(round(time() - start, 2)))

    else:
        #Help
        print("Wrong Syntax. Please refer below for correct syntax.")
        print("Usage: " + sys.argv[0] + " -sip xx.xx.xx.xx")
        print("Usage: " + sys.argv[0] + " -ip list.txt")
        print("Usage: " + sys.argv[0] + " -surl xxxxxx")
        print("Usage: " + sys.argv[0] + " -url list.txt")
        print("Usage: " + sys.argv[0] + " -url list.txt -ss")
        print("Usage: " + sys.argv[0] + " -shash xxxxx")
        print("Usage: " + sys.argv[0] + " -hash list.txt")
        print("Usage: " + sys.argv[0] + " -file list.txt")

