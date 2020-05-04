from time import sleep

from selenium import webdriver
from selenium.common.exceptions import TimeoutException
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options
from bs4 import BeautifulSoup
from urllib.parse import quote, quote_plus
import base64
import sys
import requests
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
chrome_options = Options()
chrome_options.add_argument("--window-size=1920x1080")
chrome_options.add_argument("--headless")
chrome_options.add_experimental_option('excludeSwitches', ['enable-logging']) # for debugging comment this out

class Screenshot(object):

    def __init__(self, mode, api):
        self.mode = mode
        self.api = api

    def abusedIP(self, ip):
        driver = webdriver.Chrome(executable_path=self.api.get("drive"), options=chrome_options)
        driver.get("https://www.abuseipdb.com/check/{}".format(ip))
        timeout = 10
        element_present = EC.presence_of_element_located((By.CLASS_NAME, 'well'))
        WebDriverWait(driver, timeout).until(element_present)
        try:
            driver.save_screenshot("Images/" + self.mode + "/" + self.makeFileName(ip) + "_abusedIP.png")
            driver.quit()
            return True
        except:
            driver.quit()
            return False

    def IBM(self, obj):
        driver = webdriver.Chrome(executable_path=self.api.get("drive"), options=chrome_options)
        driver.get("https://exchange.xforce.ibmcloud.com/search/{}".format(quote(obj)))
        timeout = 15
        element_present = EC.presence_of_element_located((By.CLASS_NAME, 'modal-dialog'))
        WebDriverWait(driver, timeout).until(element_present)
        # terms and condition + guest login
        driver.find_element_by_xpath("//input[@ng-model='termsCheckbox']").click()
        driver.find_element_by_xpath("//a[@ng-click='guest()']").click()
        try: # Close help pop up if there is
            element = driver.find_element_by_xpath("//button[@ng-click='$ctrl.actionButtonHandler()']")
            driver.execute_script("arguments[0].click();", element)
        except:
            pass
        # Make sure score element is there for screenshot
        element_present = EC.presence_of_element_located((By.ID, 'report'))
        WebDriverWait(driver, timeout).until(element_present)
        ## To print score
        soup = BeautifulSoup(driver.page_source, 'html.parser')
        riskLevel = soup.find('div', attrs={'class': 'scorebackgroundfilter numtitle'}).text.split()[0]
        try:
            driver.save_screenshot("Images/" + self.mode + "/" + self.makeFileName(obj) + "_ibm.png")
            driver.quit()
            print("IBM: Screenshot saved")
        except:
            driver.quit()
            print("IBM: Failed to save screenshot")
        return riskLevel

    def urlscan(self, url, uuid):
        driver = webdriver.Chrome(executable_path=self.api.get("drive"), options=chrome_options)
        driver.get("https://urlscan.io/result/{}".format(uuid))
        timeout = 20
        element_present = EC.presence_of_element_located((By.CLASS_NAME, 'container'))
        WebDriverWait(driver, timeout).until(element_present)
        try:
            driver.save_screenshot("Images/" + self.mode + "/" + self.makeFileName(url) + "_urlscan.png")
            driver.quit()
            return True
        except:
            driver.quit()
            return False


    def virusTotal(self, obj):
        driver = webdriver.Chrome(executable_path=self.api.get("drive"), options=chrome_options)
        target = obj
        identifier = self.mode
        imageName = obj
        if self.mode == 'url':
            encoded_url = base64.b64encode(obj.encode())
            target = encoded_url.decode().replace('=', '')
        elif self.mode == 'ip':
            identifier = 'ip-address'
        elif self.mode == 'hash':
            identifier = 'file'
        elif self.mode == 'file':
            target = obj[0]
        driver.get(self.api.get("vt_ss_link").format(identifier=identifier, target=target))
        timeout = 10
        element_present = EC.presence_of_element_located((By.TAG_NAME, 'vt-virustotal-app'))
        WebDriverWait(driver, timeout).until(element_present)
        ## To check scores are same with the VT API
        # root = str(driver.find_element_by_tag_name('vt-virustotal-app').text)
        # res = root.find("Community\nScore")
        # substr = root[res-10:res-1]
        # positives = int(''.join(list(filter(str.isdigit, substr.split("/")[0]))))
        # total = int(''.join(list(filter(str.isdigit, substr.split("/")[1]))))
        # rate = str(positives) + " out of " + str(total)
        # print(rate)
        try:
            driver.save_screenshot("Images/" + self.mode + "/" + self.makeFileName(obj) + "_virusTotal.png")
            driver.quit()
            return True
        except:
            driver.quit()
            return False

    # works for both ip or url
    def ciscoTalos(self, iporurl):
        # Initialise selenium driver
        driver = webdriver.Chrome(executable_path=self.api.get("drive"), options=chrome_options)
        driver.get(self.api.get("cisco_iporurl_link") + quote(iporurl))
        timeout = 20
        element_present = EC.presence_of_element_located((By.CLASS_NAME, 'new-legacy-label'))
        WebDriverWait(driver, timeout).until(element_present)
        # print("Page Loaded: " + driver.title)
        soup = BeautifulSoup(driver.page_source, 'html.parser')
        web_reputation = soup.find('span', attrs={'class': 'new-legacy-label'}).text.split()[0]
        driver.save_screenshot("Images/" + self.mode + "/" + self.makeFileName(iporurl) + "_ciscoTalos.png")
        driver.quit()
        return web_reputation

    # For url and ip
    def makeFileName(self, obj):
        imageName = obj
        if self.mode == 'url':
            imageName = obj.split("://")
            if len(imageName) >= 2:
                imageName = imageName[1].split("/")[0]
            else:
                imageName = imageName[0].split("/")[0]
        elif self.mode == 'file':
            imageName = obj[1].split("/")[-1].split(".")[0]
            target = obj[0]
        return imageName