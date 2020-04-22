# -*- coding: utf8 -*-
import requests
import json
import base64
from urllib.parse import quote
from time import sleep
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

fraudGuardKeys = "fraudguard_keys.txt"
config = "config.txt"
api = {}
hybrid_apikey = "NOT READY"

#initialise all the api keys and apis from config.txt
def init():
    with open(config) as f:
        for line in f:
            if line != "\n" and not line.startswith('['):
                (key, val) = line.split("=", 1)
                api[key.strip()] = val.strip()


# function to save result in csv file
def saveRecord(data, formula):
    if formula == "ip":
        fieldnames = ["Target", "IBM", "AbusedIP", "FraudGuard", "Auth0", "Action"]
        with open(result_ip_name, mode="a+", encoding="utf-8", newline="") as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
            if os.stat(result_ip_name).st_size == 0:
                writer.writeheader()
            malic = "Safe"
            nonzero = 0
            if data[1].startswith("1 out") == False:
                #malic = "Malicious"
                nonzero += 1
            if data[2].startswith("0 out") == False:
                #malic = "Malicious"
                nonzero += 1
            if data[3].startswith("1 out") == False:
                #malic = "Malicious"
                nonzero += 1
            if int(data[4]) != 0:
                #malic = "Malicious"
                nonzero += 1
            if nonzero > 0:
                malic = "To Block"
            writer.writerow({"Target":data[0], "IBM":data[1], "AbusedIP":data[2],"FraudGuard":data[3], "Auth0": data[4], "Action": malic})
    elif formula == "url":
        fieldnames = ["Target", "IBM", "VirusTotal","URLScan","GoogleSafeBrowsing", "URLScanUUID", "Action"]
        with open(result_url_name, mode="a+", encoding="utf-8", newline="") as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
            if os.stat(result_url_name).st_size == 0:
                writer.writeheader()
            malic = "Safe"
            nonzero = 0
            if data[1].startswith("1 out") == False:
                #malic = "Malicious"
                nonzero += 1
            if data[2].startswith("0 out") == False:
                #malic = "Malicious"
                nonzero += 1
            if data[3].startswith("0 out") == False:
                #malic = "Malicious"
                nonzero += 1
            if data[4].startswith("Safe") == False:
                #malic = "Malicious"
                nonzero += 1
            if nonzero > 0:
                malic = "To Block"
            writer.writerow({"Target":data[0], "IBM":data[1], "VirusTotal":data[2], "URLScan": data[3], "GoogleSafeBrowsing":data[4], "URLScanUUID":data[5], "Action" : malic})
    elif formula == "file":
        fieldnames = ["Target", "VirusTotal"]
        with open(result_file_name, mode="a+", encoding="utf-8", newline="") as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
            if os.stat(result_file_name).st_size == 0:
                writer.writeheader()
            writer.writerow({"Target":data[0], "VirusTotal":data[1]})
    elif formula == "hash":
        fieldnames = ["Target", "MD5", "SHA256", "SHA1", "Score"]
        with open(result_hash_name, mode="a+", encoding="utf-8", newline="") as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
            if os.stat(result_hash_name).st_size == 0:
                writer.writeheader()
            writer.writerow({"Target":data[0], "MD5":data[1], "SHA256":data[2], "SHA1":data[3], "Score":data[4]})
# only works for url, no ip support
def virusTotal(url):
    params = {
        'apikey': api.get("vt_apikey"),
        'resource': url
        }
    headers = {
            "Accept-Encoding": "gzip, deflate",
            "User-Agent": "gzip,  My Python requests library example client or username"
        }
    resp = json.loads(requests.post(api.get("vt_url_api"), params=params, headers=headers).text)
    if resp['response_code'] == 1:
        rate = str(resp['positives']) + " out of " + str(resp['total'])
    else:
        rate = "N/A"
    return rate

def virusTotalFile(a_file):
    files = {'file': (a_file.split('/')[-1], open(a_file, 'rb'))}
    params = {
        'apikey': api.get("vt_apikey"),
        }
    resp = requests.post(api.get("vt_file_api"), files=files, params=params)
    if resp.status_code != 204:
        resp2 = json.loads(resp.text)['resource']
        if delay is not None:
            sleep(delay)
        else:
            sleep(15)
        params = params = {
        'apikey': api.get("vt_apikey"),
        'resource': resp2
        }
        headers = {"Accept-Encoding": "gzip, deflate", }
        resp3 = json.loads(requests.post(api.get("vt_report_api"), params=params, headers=headers).text)
        rate = str(resp3['positives'])+' out of '+str(resp3['total'])
        return rate
    else:
        return "N/A"

def virusTotalHash(hash_value):
    params = {
        'apikey': api.get("vt_apikey"),
        'resource': hash_value
        }
    headers = {"Accept-Encoding": "gzip, deflate", }
    resp = requests.get(api.get("vt_hash_api"), params=params, headers=headers).json()
    try:
        md5 =resp['md5']
    except:
        md5 = "N/A"
    try:
        sha256 =resp['sha256']
    except:
        sha256 = "N/A"
    try:
        sha1 =resp['sha1']
    except:
        sha1 = "N/A"
    try:
        score = str(resp['positives'])+' out of '+str(resp['total'])
    except:
        score = "N/A"
    return [hash_value, md5, sha256, sha1, score]

# only works for url, no ip support
def abusedIP(ip):
    headers = {
            'Key': api.get("abip_apikey"),
            'Accept': 'application/json',
        }
    params = {
            'ipAddress': ip,
        }
    resp = json.loads(requests.get(api.get("abip_apikey"), headers=headers,params=params).text)
    rate = str(resp['data']["abuseConfidenceScore"]) + " out of 100"
    return rate

# call to this function when url mode on
def IBM_URL(url):
    pass_data = api.get("ibm_apikey") + ":" + api.get("ibm_apipass")
    data = base64.b64encode(pass_data.encode())
    final = str(data.decode('utf-8'))
    headers = {"Authorization": "Basic "+final, "Content-Type":"application/json"}
    resp = json.loads(requests.get(api.get("ibm_url_api") + quote(url), headers=headers).text)
    rate = str(resp['result']['score']) + " out of 10"
    return rate

# call to this function when ip mode on
def IBM_IP(ip):
    pass_data = api.get("ibm_apikey") + ":" + api.get("ibm_apipass")
    data = base64.b64encode(pass_data.encode())
    final = str(data.decode('utf-8'))
    headers = {"Authorization": "Basic "+final, "Content-Type":"application/json"}
    resp = json.loads(requests.get(api.get("ibm_ip_api") + ip, headers=headers).text)
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
    headers = {
        "API-Key": api.get("urlscan_apikey")
        }
    data = {
        "url": url
        }
    resp = requests.post(api.get("urlscan_api"),data=data,headers=headers).text
    uuid = json.loads(resp)['uuid']
    nextpage = json.loads(resp)['api']
    if delay is not None:
        sleep(delay)
    else:
        sleep(60)
    result = requests.get(nextpage).json()
    score = result['verdicts']['overall']['score']
    sleep(2)
    with open("images/" + uuid + ".png", "wb+") as img_sc:
        try:
            img_sc.write(requests.get(api.get("urlscan_screenshot") + uuid + ".png").content)
        except:
            pass
    return [str(score) + " out of 100", uuid]

def googleSafe(url):
    headers = {
        "Content-Type": "application/json"
        }
    data = {"client":{"clientId":"mitreautoz","clientVersion":"1.5.2"},"threatInfo":{"threatTypes":["MALWARE", "SOCIAL_ENGINEERING"],"platformTypes":["WINDOWS"],"threatEntryTypes":["URL"],"threatEntries":[{"url": url}]}}
    resp = requests.post(api.get("google_api")+api.get("google_apikey"),data=json.dumps(data)).json()
    if "matches" in resp.keys():
        return resp["matches"][0]["threatType"]
    else:
        return "Safe"

def auth0(ip):
    headers = {
        "Accept": "application/json",
        "X-Auth-Token":api.get("auth0_apikey")
        }
    resp = requests.get(api.get("auth0_api") + ip,headers=headers).json()
    return resp['fullip']['score']

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

if __name__ == "__main__":
    init()
    #print(hybrid("https://chase.com.onlinesecuremyaccount.locked.situstaruhanqq820.com/"))
    try:
        os.mkdir("images")
        os.mkdir("images_hybrid")
    except:
        pass
    #print(urlscan("https://en.wikipedia.org/wiki/Anime"))
    ip_mode = False
    url_mode = False
    file_mode = False
    hash_mode = False
    delay = None
    file_to_read = None
    sip_mode = False
    surl_mode = False
    shash_mode = False
    if len(sys.argv) < 3:
        print("Usage: " + sys.argv[0] + " -url list.txt")
        print("Usage: " + sys.argv[0] + " -ip list.txt")
        print("Usage: " + sys.argv[0] + " -url list.txt -d 15")
        print("Usage: " + sys.argv[0] + " -ip list.txt -d 15")
        print("Usage: " + sys.argv[0] + " -hash list.txt")
        print("Usage: " + sys.argv[0] + " -hash list.txt -d 15")
        print("Usage(virustotal only): " + sys.argv[0] + " -file list.txt")
        print("Usage(virustotal only): " + sys.argv[0] + " -file list.txt -d 15")
        print("Usage: " + sys.argv[0] + " -sip 127.0.0.1")
        print("Usage: " + sys.argv[0] + " -surl URL")
        print("Usage: " + sys.argv[0] + " -shash HASH")
    else:
        ok = False
        #with -d
        if len(sys.argv) == 5:
            if sys.argv[1] == "-url":
                url_mode = True
            elif sys.argv[1] == "-ip":
                ip_mode = True
            elif sys.argv[1] == "-file":
                file_mode = True
            elif sys.argv[1] == "-hash":
                hash_mode = True
            delay = int(sys.argv[4])
            file_to_read = sys.argv[2]
            ok = True
        #without -d
        elif len(sys.argv) == 3:
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
            ok = True
        else:
            print("Usage: " + sys.argv[0] + " -url list.txt")
            print("Usage: " + sys.argv[0] + " -ip list.txt")
            print("Usage: " + sys.argv[0] + " -url list.txt -d 15")
            print("Usage: " + sys.argv[0] + " -ip list.txt -d 15")
            print("Usage: " + sys.argv[0] + " -hash list.txt")
            print("Usage: " + sys.argv[0] + " -hash list.txt -d 15")
            print("Usage(virustotal only): " + sys.argv[0] + " -file list.txt")
            print("Usage(virustotal only): " + sys.argv[0] + " -file list.txt -d 15")
        if sip_mode:
            ok = False
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
                vt = virusTotal(file_to_read)
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
            except:
                gsb = "N/A"
            print("GoogleSafeBrowsing: " + gsb)
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
                    print("IN USE: " + ip)
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
                    dataset.append(abip)
                    dataset.append(fg)
                    dataset.append(ath0)
                    saveRecord(dataset,"ip")
                    if delay is not None:
                        sleep(delay)
            elif url_mode == True:
                for url in file_data:
                    if url == "":
                        continue
                    print("IN USE: " + url)
                    try:
                        vt = virusTotal(url)
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
                    except:
                        gsb = "N/A"
                    print("GoogleSafeBrowsing: " + gsb)
                    dataset = []
                    dataset.append(url)
                    dataset.append(ibm_rec)
                    dataset.append(vt)
                    dataset.append(usc)
                    dataset.append(gsb)
                    dataset.append(uscuuid)
                    saveRecord(dataset,"url")
                    if delay is not None:
                        sleep(delay)
            elif file_mode == True:
                for a_file in file_data:
                    if a_file == "":
                        continue
                    try:
                        res = virusTotalFile(a_file)
                    except:
                        res = "N/A"
                    dataset = []
                    dataset.append(a_file)
                    dataset.append(res)
                    saveRecord(dataset,"file")
                    if delay is not None:
                        sleep(delay)
            elif hash_mode == True:
                for a_hash in file_data:
                    if a_hash == "":
                        continue
                    try:
                        hv = virusTotalHash(a_hash)
                        saveRecord(hv, "hash")
                        print("Data saved for " + a_hash)
                    except:
                        hv = []
                        print("No data saved for " + a_hash)
                    if delay is not None:
                        sleep(delay)