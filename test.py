import base64
import json
import os
import sys
from time import sleep

import hashlib

import requests
delay = 60
api={}

def md5(fname):
    hash_md5 = hashlib.md5()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

def init():
    with open("config.txt") as f:
        for line in f:
            if line != "\n" and not line.startswith('['):
                (key, val) = line.split("=", 1)
                api[key.strip()] = val.strip()

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


def checkExceptionVT(code):
    if code == 401:
        raise Exception("ERROR: Please verify API KEY!")
    elif code == 429:
        raise Exception("ERROR: Requests Exceeded!")
    elif code != 200:
        raise Exception("")

def virusTotalFile(file):
    if not os.path.isfile(file):
        raise Exception('File not found. Please submit a valid file path')
    headers = {
        'x-apikey': api.get("vt_apikey"),
        'Accept': 'application/json'
    }
    with open(file, 'rb') as f:
        data = {'file': f.read()}

    #upload file based on size
    file_size = os.path.getsize(file)
    if file_size <= 33554432:
        res = requests.post(api.get("vt_file_api"), headers=headers, files=data)
    else:  # bigger than 32 mb - there may be performance issue as a file gets too big
        res = requests.get(api.get("vt_file_api") + '/upload_url', headers=headers)
        checkExceptionVT(res.status_code)
        upload_url = res.json()['data']
        res = requests.post(upload_url, headers=headers, files=data)
    checkExceptionVT(res.status_code)

    #retrieve analysis
    filehash = str(md5(file))
    return virusTotalHash3(filehash)[4]

def virusTotalHash3(hash):
    headers = {
        'x-apikey': api.get("vt_apikey"),
        'Accept': 'application/json'
    }
    res = requests.get(api.get("vt_file_api") + '/{}'.format(hash), headers=headers)
    checkExceptionVT(res.status_code)
    harmless = int(res.json()['data']['attributes']['last_analysis_stats']['harmless'])
    malicious = int(res.json()['data']['attributes']['last_analysis_stats']['malicious'])
    suspicious = int(res.json()['data']['attributes']['last_analysis_stats']['suspicious'])
    undetected = int(res.json()['data']['attributes']['last_analysis_stats']['undetected'])
    rate = str(malicious + suspicious) + " out of " + str(malicious + harmless + suspicious + undetected)
    # Status: confirmed-timeout, failure, harmless, malicious, suspicious, timeout, type-unsupported, undetected
    md5 = res.json()['data']['attributes']['md5']
    sha256 = res.json()['data']['attributes']['sha256']
    sha1 = res.json()['data']['attributes']['sha1']
    return [hash, md5, sha256, sha1, rate]

if __name__ == "__main__":
    init()
    file_to_read = sys.argv[2]
    print(file_to_read)
    file_data = open(file_to_read, 'r').read().split('\n')
    for file in file_data:
        if file == "":
            continue
        print("IN USE: " + file)
        try:
            vt = virusTotalFile(file)
        except Exception as error:
            print(str(error))
            vt = "N/A"
        print("VirusTotal: " + str(vt))
