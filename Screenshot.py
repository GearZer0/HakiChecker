from selenium import webdriver
from selenium.common.exceptions import WebDriverException
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options
from bs4 import BeautifulSoup
from urllib.parse import quote
import base64
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

# Selenium driver options
import Constant as C

options = Options()
options.add_argument("--window-size=1680x1050")
options.add_argument("--headless")
options.add_experimental_option('excludeSwitches', ['enable-logging'])  # for debugging comment this out
timeout = 20


class Screenshot(object):

    def __init__(self, mode, key):
        self.mode = mode
        self.key = key
        self.imageName = ""

    def phishtank(self, url):
        driver = webdriver.Chrome(executable_path=self.key.get("drive"), options=options)
        driver.get(C.PHISH_SS)
        try:
            element_present = EC.presence_of_element_located((By.ID, 'main'))
            WebDriverWait(driver, timeout).until(element_present)
            input = driver.find_element_by_xpath("//input[@type='text' and @name='isaphishurl' and @value='http://']")
            input.clear()
            input.send_keys(url)
            driver.find_element_by_xpath("//input[@type='submit' and @class='submitbutton']").click()
            driver.save_screenshot(self.imageName.format(C.PHISH))
            driver.quit()
            return True
        except WebDriverException:
            driver.quit()
            return False

    def auth0(self, ip):
        driver = webdriver.Chrome(executable_path=self.key.get("drive"), options=options)
        driver.get(C.AUTH0_SS.format(ip))
        try:
            element_present = EC.presence_of_element_located((By.XPATH, '//section[@data-results-register="true"]'))
            WebDriverWait(driver, timeout).until(element_present)
            driver.execute_script("window.scrollTo(0, 200)")
            driver.save_screenshot(self.imageName.format(C.AUTH0))
            driver.quit()
            return True
        except WebDriverException:
            driver.quit()
            return False

    def googleSafe(self, url):
        driver = webdriver.Chrome(executable_path=self.key.get("drive"), options=options)
        driver.get(C.GOOGLE_SS.format(url))
        try:
            element_present = EC.presence_of_element_located((By.TAG_NAME, 'data-tile'))
            WebDriverWait(driver, timeout).until(element_present)
            driver.save_screenshot(self.imageName.format(C.GOOGLE))
            driver.quit()
            return True
        except WebDriverException:
            driver.quit()
            return False

    def fraudguard(self, ip):
        driver = webdriver.Chrome(executable_path=self.key.get("drive"), options=options)
        driver.get(C.FG_SS.format(ip))
        try:
            element_present = EC.presence_of_element_located((By.CLASS_NAME, 'col-md-6'))
            WebDriverWait(driver, timeout).until(element_present)
            driver.execute_script("window.scrollTo(0, 500)")
            driver.save_screenshot(self.imageName.format(C.FG))
            driver.quit()
            return True
        except WebDriverException:
            driver.quit()
            return False

    def abusedIP(self, ip):
        driver = webdriver.Chrome(executable_path=self.key.get("drive"), options=options)
        driver.get(C.ABIP_SS.format(ip))
        try:
            element_present = EC.presence_of_element_located((By.CLASS_NAME, 'well'))
            WebDriverWait(driver, timeout).until(element_present)
            driver.save_screenshot(self.imageName.format(C.ABIP))
            driver.quit()
            return True
        except WebDriverException:
            driver.quit()
            return False

    # for url and ip
    def IBM(self, obj):
        driver = webdriver.Chrome(executable_path=self.key.get("drive"), options=options)
        driver.get(C.IBM_SS.format(quote(obj)))
        element_present = EC.presence_of_element_located((By.CLASS_NAME, 'modal-dialog'))
        WebDriverWait(driver, timeout).until(element_present)
        # terms and condition + guest login
        driver.find_element_by_xpath("//input[@ng-model='termsCheckbox']").click()
        driver.find_element_by_xpath("//a[@ng-click='guest()']").click()
        try:  # Close help pop up if there is
            element = driver.find_element_by_xpath("//button[@ng-click='$ctrl.actionButtonHandler()']")
            driver.execute_script("arguments[0].click();", element)
        except WebDriverException:
            pass
        # Make sure score element is there for screenshot
        element_present = EC.presence_of_element_located((By.ID, 'report'))
        WebDriverWait(driver, timeout).until(element_present)
        ## To print score
        soup = BeautifulSoup(driver.page_source, 'html.parser')
        riskLevel = soup.find('div', attrs={'class': 'scorebackgroundfilter numtitle'}).text.split()[0]
        try:
            driver.save_screenshot(self.imageName.format(C.IBM))
            print(C.IBM + ": " + C.SS_SAVED)
        except WebDriverException:
            print(C.IBM + ": " + C.SS_FAILED)
        driver.quit()
        return riskLevel

    def urlscan(self, url, uuid):
        driver = webdriver.Chrome(executable_path=self.key.get("drive"), options=options)
        driver.get(C.URLSCAN_SS.format(uuid))
        try:
            element_present = EC.presence_of_element_located((By.CLASS_NAME, 'container'))
            WebDriverWait(driver, timeout).until(element_present)
            driver.save_screenshot(self.imageName.format(C.URLSCAN))
            driver.quit()
            return True
        except WebDriverException:
            driver.quit()
            return False

    def virusTotal(self, obj):
        driver = webdriver.Chrome(executable_path=self.key.get("drive"), options=options)
        target = obj
        identifier = self.mode
        if self.mode == C.URL_MODE:
            encoded_url = base64.b64encode(obj.encode())
            target = encoded_url.decode().replace('=', '')
        elif self.mode == C.IP_MODE:
            identifier = 'ip-address'
        elif self.mode == C.HASH_MODE:
            identifier = 'file'
        elif self.mode == C.FILE_MODE:
            target = obj[0]
            self.makeFileName(obj)
        driver.get(C.VT_SS.format(identifier=identifier, target=target))
        try:
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
            driver.save_screenshot(self.imageName.format(C.VT))
            driver.quit()
            return True
        except WebDriverException:
            driver.quit()
            return False

    # works for both ip or url
    def ciscoTalos(self, iporurl):
        # Initialise selenium driver
        driver = webdriver.Chrome(executable_path=self.key.get("drive"), options=options)
        driver.get(C.CISCO_SS + quote(iporurl))
        try:
            element_present = EC.presence_of_element_located((By.CLASS_NAME, 'new-legacy-label'))
            WebDriverWait(driver, timeout).until(element_present)
            soup = BeautifulSoup(driver.page_source, 'html.parser')
            web_reputation = soup.find('span', attrs={'class': 'new-legacy-label'}).text.split()[0]
            driver.save_screenshot(self.imageName.format(C.CISCO))
            print(C.CISCO + ": " + C.SS_SAVED)
        except WebDriverException:
            print(C.CISCO + ": " + C.SS_FAILED)
        driver.quit()

        if web_reputation == "Unknown":
            web_reputation = C.NONE
        return web_reputation

    # For url and ip
    def makeFileName(self, obj):
        name = obj
        if self.mode == C.URL_MODE:
            name = obj.split("://")
            if len(name) >= 2:
                name = name[1].split("/")[0]
            else:
                name = name[0].split("/")[0]
        elif self.mode == C.FILE_MODE:
            name = obj[1].split("/")[-1].split(".")[0]
        self.imageName = "Images/" + self.mode + "/" + name + "_{}.png"

