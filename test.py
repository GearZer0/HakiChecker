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


def getFGKey():
    keys = open(FG_KEYS, 'r').read().split('\n')
    if keys == "":
        print("Are you sure about FG Keys availability?")
    return keys[0]

def removeOldFGKey(get_key):
    keys = open(FG_KEYS, 'r').read().split('\n')
    open(FG_KEYS, 'w+').close()
    with open(FG_KEYS, 'a+') as fl:
        for i in keys:
            if i != get_key:
                fl.write(i + "\n")
        fl.write(get_key + "\n")

def fraudGuard(ip):
    ss.fraudguard(ip)
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

if __name__ == "__main__":
    init()
    ss = Screenshot.Screenshot('ip', api)
    file_to_read = sys.argv[2]
    print(file_to_read)
    file_data = open(file_to_read, 'r').read().split('\n')
    for ip in file_data:
        if ip == "":
            continue
        print("IN USE: " + ip)
        try:
            ct = fraudGuard(ip)
        except TimeoutException as e:
            print("Time out")
            ct = "N/A"
        except Exception as e:
            print(e)
            ct = "N/A"
            pass
        pass
        print("fraudguard: " + str(ct))
