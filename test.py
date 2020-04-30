
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

def ciscoTalos(ip):
    # Initialise selenium driver
    chrome_options = Options()
    chrome_options.add_argument("--headless")
    chrome_options.add_argument("--window-size=1325x744")
    chrome_options.add_experimental_option('excludeSwitches', ['enable-logging']) # for debugging comment this out
    driver = webdriver.Chrome(executable_path="C:/Users/***REMOVED***/Downloads/chromedriver.exe", options=chrome_options)
    driver.get("https://talosintelligence.com/reputation_center/lookup?search=" + quote(ip))
    timeout = 10
    element_present = EC.presence_of_element_located((By.ID, 'email-data-wrapper'))
    WebDriverWait(driver, timeout).until(element_present)
    # print("Page Loaded: " + driver.title)
    soup = BeautifulSoup(driver.page_source, 'html.parser')
    web_reputation = soup.find('span', attrs={'class': 'new-legacy-label'}).text.split()[0]
    imageName = ip.split("://")
    if len(imageName) == 2:
        imageName = imageName[1].split("/")
    driver.save_screenshot("Images/" + imageName[0] + "_ciscoTalos.png")
    driver.quit()
    return web_reputation

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
            ct = ss.ciscoTalos(ip)
        except TimeoutException as e:
            print("Time out")
            ct = "N/A"
        except Exception as e:
            print(e)
            ct = "N/A"
            pass
        pass
        print("VirusTotal: " + str(ct))
