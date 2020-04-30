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
    if ss.urlscan(url, uuid):
        print("Screenshot done")
    score = result.json()['verdicts']['overall']['score']

    with open("Images/" + 'url' + "/" + ss.makeFileName(url) + ".png", "wb+") as img_sc:
        try:
            img_sc.write(requests.get(api.get("urlscan_screenshot") + uuid + ".png").content)
            print("URLscan: URL Screenshot saved")
        except:
            print("URLscan: Failed to save URL screenshot")
    return [str(score) + " out of 100", uuid]

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
            ct = urlscan(ip)
        except TimeoutException as e:
            print("Time out")
            ct = "N/A"
        except Exception as e:
            print(e)
            ct = "N/A"
            pass
        pass
        print("VirusTotal: " + str(ct))
