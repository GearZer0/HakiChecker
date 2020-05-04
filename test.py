import json
from time import time, sleep

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

def getScreenshotIBM(obj):
    if ss_mode:
        if ss.IBM(obj):
            print("IBM: Screenshot saved")
        else:
            print("IBM: Failed to save screenshot")

# call to this function when url mode on
def IBM_URL(url):
    getScreenshotIBM(url)
    resp = json.loads(requests.get(api.get("ibm_url_api") + quote(url), headers=ibm_headers).text)
    rate = str(resp['result']['score']) + " out of 10"
    return rate

# call to this function when ip mode on
def IBM_IP(ip):
    getScreenshotIBM(ip)
    resp = json.loads(requests.get(api.get("ibm_ip_api") + ip, headers=ibm_headers).text)
    rate = str(resp['history'][-1]['score']) + " out of 10"
    return rate

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
            ct = IBM_URL(ip)
        except TimeoutException as e:
            print("Time out")
            ct = "N/A"
        except Exception as e:
            print(e)
            ct = "N/A"
            pass
        pass
        print("IBM: " + str(ct))
