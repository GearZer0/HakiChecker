import base64
import json
import os
import sys
from time import sleep, time

import hashlib
from urllib.parse import quote

import requests
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
    while result.status_code == 404 and time_elapsed < 65:
        sleep(5)
        result = requests.get(nextpage)
        time_elapsed = time() - start
    print(time_elapsed)
    score = result.json()['verdicts']['overall']['score']
    with open("images/" + uuid + ".png", "wb+") as img_sc:
        try:
            img_sc.write(requests.get(api.get("urlscan_screenshot") + uuid + ".png").content)
        except:
            pass
    return [str(score) + " out of 100", uuid]


if __name__ == "__main__":
    init()
    file_to_read = sys.argv[2]
    print(file_to_read)
    file_data = open(file_to_read, 'r').read().split('\n')
    for url in file_data:
        if url == "":
            continue
        print("IN USE: " + url)
        try:
            usc = urlscan(url)
            uscuuid = usc[1]
            usc = usc[0]
        except:
            usc = "N/A"
            uscuuid = "N/A"
        print("URLscan: " + usc)
