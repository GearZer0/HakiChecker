import json
from time import time, sleep

from requests.auth import HTTPBasicAuth
from selenium import webdriver
from selenium.common.exceptions import TimeoutException
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options
from bs4 import BeautifulSoup
from urllib.parse import quote
import base64
import sys

import requests
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

import Screenshot

delay = 15
api={}
ss_mode = True
FG_KEYS = "fraudguard_keys.txt"

vt_headers = {'Accept': 'application/json'}
ibm_headers = {"Content-Type": "application/json"}
#initialise all the api keys and apis from config.txt
def init():
    with open("config.txt") as f:
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

def checkExceptionGS(code):
    if code == 403:
        raise Exception("ERROR: Please verify API KEY!")
    elif code == 429:
        raise Exception("ERROR: Requests Exceeded!")
    elif code != 200:
        raise Exception("")

def googleSafe(url):
    ss.googleSafe(url)
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

if __name__ == "__main__":
    init()
    ss = Screenshot.Screenshot('url', api)
    file_to_read = sys.argv[2]
    print(file_to_read)
    file_data = open(file_to_read, 'r').read().split('\n')
    for ip in file_data:
        if ip == "":
            continue
        print("IN USE: " + ip)
        try:
            ct = googleSafe(ip)
        except TimeoutException as e:
            print("Time out")
            ct = "N/A"
        except Exception as e:
            print(e)
            ct = "N/A"
            pass
        pass
        print("fraudguard: " + str(ct))
