import hashlib
import json
import logging
import os
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
import Constant as C
import requests
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

import Screenshot

delay = 15
key={}
ss_mode = True
FG_KEYS = "fraudguard_keys.txt"

vt_headers = {'Accept': 'application/json'}
ibm_headers = {"Content-Type": "application/json"}
#initialise all the api keys and apis from config.txt
def init():
    # create logger
    logging.basicConfig(filename="hakichecker.log", level=logging.DEBUG, format="%(asctime)s:%(levelname)s:%(message)s")
    # initialise all the api keys and apis from config.txt
    with open(C.CONFIG) as f:
        for line in f:
            if line != "\n" and not line.startswith('['):
                (k, val) = line.split("=", 1)
                key[k.strip()] = val.strip()
    logging.info("Keys have been loaded")
    # Initialise vt_header
    vt_headers['x-apikey'] = key.get("vt_key")

    # Initialise ibm_header
    pass_data = key.get("ibm_key") + ":" + key.get("ibm_pass")
    data = base64.b64encode(pass_data.encode())
    final = str(data.decode('utf-8'))
    ibm_headers['Authorization'] = "Basic " + final

    # Create Directory
    try:
        os.mkdir("Images")
    except FileExistsError as e:
        logging.warning(e)
    try:
        os.mkdir("Images/ip")
    except FileExistsError as e:
        logging.warning(e)
    try:
        os.mkdir("Images/url")
    except FileExistsError as e:
        logging.warning(e)
    try:
        os.mkdir("Images/hash")
    except FileExistsError as e:
        logging.warning(e)
    try:
        os.mkdir("Images/file")
    except FileExistsError as e:
        logging.warning(e)
    try:
        os.mkdir("Results")
    except FileExistsError as e:
        logging.warning(e)
    # os.mkdir("images_hybrid")


def vt_result(result):
    try:
        harmless = int(result.json()['data']['attributes']['last_analysis_stats']['harmless'])
        malicious = int(result.json()['data']['attributes']['last_analysis_stats']['malicious'])
        suspicious = int(result.json()['data']['attributes']['last_analysis_stats']['suspicious'])
        undetected = int(result.json()['data']['attributes']['last_analysis_stats']['undetected'])
        rate = str(malicious) + " out of " + str(malicious + harmless + suspicious + undetected)
    except (KeyError, TypeError) as e:
        logging.error(C.VT + " - vt_result() - " + str(e))
        rate = C.NONE
    except Exception as e:
        logging.critical(C.VT + " - vt_result() - " + str(e))
        rate = C.NONE
    finally:
        return rate


# Get MD5 hash
def getmd5(fname):
    hash_md5 = hashlib.md5()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()


def vt_exception(resp):
    # https://developers.virustotal.com/v3.0/reference#errors
    code = resp.status_code
    if not str(code).startswith('2'):
        try:
            msg = resp.json()['error']['message']
        except ValueError as e:
            msg = e
        if code == 401 or code == 503 or code == 429:
            print(C.VT + ": ERROR - " + msg)
        raise Exception(msg)


def vt_screenshot(obj):
    if ss_mode:
        if ss.virusTotal(obj):
            print(C.VT + ": " + C.SS_SAVED)
        else:
            print(C.VT + ": " + C.SS_FAILED)


def virusTotalIP(ip):
    vt_screenshot(ip)
    try:
        resp = requests.get(C.VT_IP.format(ip), headers=vt_headers)
        vt_exception(resp)
    except Exception as e:
        vt = C.NONE
        logging.exception(C.VT + " - " + str(e))
    else:
        # available status: harmless, malicious, suspicious, timeout, undetected
        vt = vt_result(resp)
    finally:
        print(C.VT + ": " + vt)
        logging.info(C.VT + " - " + vt)
        return vt


def virusTotalURL(url):
    try:  # send url to scan
        resp = requests.post(C.VT_URL, headers=vt_headers, data={'url': url})
        vt_exception(resp)
        req_id = resp.json()['data']['id'].split('-')[1]
    except Exception as e:
        logging.error(C.VT + " - " + str(e))
    try:
        # fetch scan results
        resp = requests.get(
            C.VT_URL + '/{}'.format(req_id),
            headers=vt_headers)
        vt_exception(resp)
        # Check if the analysis is finished before returning the results
        while not resp.json()['data']['attributes']['last_analysis_results']:
            resp = requests.get(
                C.VT_URL + '/{}'.format(req_id),
                headers=vt_headers)
            sleep(3)
        vt_exception(resp)
    except Exception as e:
        vt = C.NONE
        logging.exception(C.VT + " - " + str(e))
    else:
        # available status: harmless, malicious, suspicious, timeout, undetected
        vt = vt_result(resp)
    finally:
        vt_screenshot(url)
        print(C.VT + ": " + vt)
        logging.info(C.VT + " - " + vt)
        return vt

if __name__ == "__main__":
    init()
    ss = Screenshot.Screenshot('url', key)
    file_to_read = sys.argv[2]
    print(file_to_read)
    file_data = open(file_to_read, 'r').read().split('\n')
    for ip in file_data:
        if ip == "":
            continue
        if ss_mode:
            ss.makeFileName(ip)
        print("IN USE: " + ip)
        vt = virusTotalIP(ip)
