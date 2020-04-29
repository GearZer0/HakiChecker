from time import sleep

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
chrome_options = Options()
chrome_options.add_argument("--headless")
chrome_options.add_argument("--window-size=1325x744")
chrome_options.add_experimental_option('excludeSwitches', ['enable-logging']) # for debugging comment this out



def virusTotalIP(ip):
    driver = webdriver.Chrome(executable_path="C:/Users/***REMOVED***/Downloads/chromedriver.exe", options=chrome_options)
    driver.get("https://www.virustotal.com/gui/ip-address/{}/detection".format(quote(ip)))
    timeout = 10
    element_present = EC.presence_of_element_located((By.TAG_NAME, 'vt-virustotal-app'))
    WebDriverWait(driver, timeout).until(element_present)
    root = str(driver.find_element_by_tag_name('vt-virustotal-app').text)
    ## To check scores are same with the VT API
    # res = root.find("Community\nScore")
    # substr = root[res-10:res-1]
    # positives = int(''.join(list(filter(str.isdigit, substr.split("/")[0]))))
    # total = int(''.join(list(filter(str.isdigit, substr.split("/")[1]))))
    imageName = ip.split("://")
    if len(imageName) == 2:
        imageName = imageName[1].split("/")
    try:
        driver.save_screenshot("Images/" + imageName[0] + "_virusTotal.png")
        driver.quit()
        return True
    except:
        driver.quit()
        return False
    # return str(positives) + " out of " + str(total)



