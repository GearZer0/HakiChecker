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


def phishtank(url):
    ss.phishtank(url)
    data = {
        "url": url,
        'format': "json",
        'app_key': api.get("phish_apikey")
        }
    headers = {
        "User-Agent": "phishtank/" + api.get("phish_user")
        }
    resp = requests.post(api.get("phish_api"), headers=headers, data=data)
    if resp.status_code == 509:
        raise Exception("ERROR: Requests Exceeded! Please wait at most 5 minutes to reset the number of requests.")
    elif resp.status_code != 200:
        raise Exception("")
    if resp.json()['results']['in_database']: # if it exists in database
        if not resp.json()['results']['verified']: # if pending verification return malicious
            return "Questionable"
        elif resp.json()['results']['verified'] and resp.json()['results']['valid']: # if verified as phish, return malicious
            return "Phish"
        else: # if verified as not a phish
            return False
    return False # if not in database

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
            ct = phishtank(ip)
        except TimeoutException as e:
            print("Time out")
            ct = "N/A"
        except Exception as e:
            print(e)
            ct = "N/A"
            pass
        pass
        print("auth0: " + str(ct))
