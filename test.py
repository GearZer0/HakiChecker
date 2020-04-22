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

def virusTotalFile(a_file):
    files = {'file': (a_file.split('/')[-1], open(a_file, 'rb'))}
    params = {
        'apikey': api.get("vt_apikey"),
        }
    resp = requests.post(api.get("vt_file_api_old"), files=files, params=params)
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

def virusTotalFile3(file):
    if not os.path.isfile(file):
        raise Exception('File not found. Please submit a valid file path')
    headers = {
        'x-apikey': api.get("vt_apikey"),
        'Accept': 'application/json'
    }
    with open(file, 'rb') as f:
        data = {'file': f.read()}
    file_size = os.path.getsize(file)
    if file_size < 33554432:
        res = requests.post(api.get("vt_file_api"), headers=headers, files=data)
        if res.status_code == 401:
            raise Exception("Error! Please verify API KEY!")
        elif res.status_code == 429:
            raise Exception("Error! Requests Exceeded!")
        elif res.status_code != 200:
            raise Exception("")
        filehash = str(md5(file))
        res = requests.get(api.get("vt_file_api") + '/{}'.format(filehash), headers=headers)
        if res.status_code == 200:
            rate = str(res.json()['data']['attributes'][''])
            harmless = int(res.json()['data']['attributes']['last_analysis_stats']['harmless'])
            malicious = int(res.json()['data']['attributes']['last_analysis_stats']['malicious'])
            suspicious = int(res.json()['data']['attributes']['last_analysis_stats']['suspicious'])
            #timeout = int(res.json()['data']['attributes']['last_analysis_stats']['timeout'])
            undetected = int(res.json()['data']['attributes']['last_analysis_stats']['undetected'])
            rate = str(malicious + suspicious) + " out of " + str(
                malicious + harmless + suspicious + undetected)

            #"confirmed-timeout"
            # "failure"
            # "harmless"
            # "malicious"
            # "suspicious"
            # "timeout"
            # "type-unsupported"
            # "undetected"
        elif res.status_code == 429:
            raise Exception("Error! Requests Exceeded!")
        else:
            print(res.status_code)
            rate = "N/A"
            # for debugging
            # print("Error " + str(resp.status_code) + ": " + str(resp))
    else:
        raise Exception('File size is bigger than 32MB!')

    return rate




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
            vt = virusTotalFile3(file)
        except requests.exceptions.RequestException as error:
            print(str(error))
            vt = "N/A"
        except Exception as error:
            print(str(error))
            vt = "N/A"
        print("VirusTotal: " + vt)
