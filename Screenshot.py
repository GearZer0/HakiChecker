import logging
from selenium import webdriver
from selenium.common.exceptions import *
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options
from bs4 import BeautifulSoup
from urllib.parse import quote
import base64
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import Constant as C

# Selenium driver options
options = Options()
options.add_argument("--window-size=1680x1050")
options.add_experimental_option("excludeSwitches", ["enable-automation", 'enable-logging'])
options.add_experimental_option('useAutomationExtension', False)
options.add_argument("--headless")
timeout = 20


class Screenshot(object):

    def __init__(self, mode, key):
        self.mode = mode
        self.key = key
        self.imageName = ""
        logging.info("Initialised Screenshot mode with identifier " + mode)

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
            saved = True
            logging.info(C.PHISH + " - Screenshot saved at " + self.imageName.format(C.PHISH))
        except WebDriverException:
            logging.exception(C.PHISH + " - Screenshot")
            saved = False
        finally:
            driver.quit()
            return saved

    def auth0(self, ip):
        driver = webdriver.Chrome(executable_path=self.key.get("drive"), options=options)
        driver.get(C.AUTH0_SS.format(ip))
        try:
            element_present = EC.presence_of_element_located((By.XPATH, '//section[@data-results-register="true"]'))
            WebDriverWait(driver, timeout).until(element_present)
            driver.execute_script("window.scrollTo(0, 200)")
            driver.save_screenshot(self.imageName.format(C.AUTH0))
            saved = True
            logging.info(C.AUTH0 + " - Screenshot saved at " + self.imageName.format(C.AUTH0))
        except WebDriverException:
            logging.exception(C.AUTH0 + " - Screenshot")
            saved = False
        finally:
            driver.quit()
            return saved

    def googleSafe(self, url):
        driver = webdriver.Chrome(executable_path=self.key.get("drive"), options=options)
        driver.get(C.GOOGLE_SS.format(url))
        try:
            element_present = EC.presence_of_element_located((By.TAG_NAME, 'data-tile'))
            WebDriverWait(driver, timeout).until(element_present)
            driver.save_screenshot(self.imageName.format(C.GOOGLE))
            saved = True
            logging.info(C.GOOGLE + " - Screenshot saved at " + self.imageName.format(C.GOOGLE))
        except WebDriverException:
            logging.exception(C.GOOGLE + " - Screenshot")
            saved = False
        finally:
            driver.quit()
            return saved

    def fraudguard(self, ip):
        driver = webdriver.Chrome(executable_path=self.key.get("drive"), options=options)
        driver.get(C.FG_SS.format(ip))
        try:
            element_present = EC.presence_of_element_located((By.CLASS_NAME, 'col-md-6'))
            WebDriverWait(driver, timeout).until(element_present)
            driver.execute_script("window.scrollTo(0, 500)")
            driver.save_screenshot(self.imageName.format(C.FG))
            saved = True
            logging.info(C.FG + " - Screenshot saved at " + self.imageName.format(C.FG))
        except WebDriverException:
            logging.exception(C.FG + " - Screenshot")
            saved = False
        finally:
            driver.quit()
            return saved

    def abusedIP(self, ip):
        driver = webdriver.Chrome(executable_path=self.key.get("drive"), options=options)
        driver.get(C.ABIP_SS.format(ip))
        try:
            element_present = EC.presence_of_element_located((By.CLASS_NAME, 'well'))
            WebDriverWait(driver, timeout).until(element_present)
            driver.save_screenshot(self.imageName.format(C.ABIP))
            saved = True
            logging.info(C.ABIP + " - Screenshot saved at " + self.imageName.format(C.ABIP))
        except WebDriverException:
            logging.exception(C.ABIP + " - Screenshot")
            saved = False
        finally:
            driver.quit()
            return saved

    # for url and ip
    def IBM(self, obj):
        driver = webdriver.Chrome(executable_path=self.key.get("drive"), options=options)
        # driver.implicitly_wait(5)
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
            logging.exception(C.IBM + " - Screenshot")
            pass
        # Make sure score element is there for screenshot
        # element_present = EC.presence_of_element_located((By.ID, 'report'))
        # WebDriverWait(driver, timeout).until(element_present)
        ## To print score
        try:
            driver.find_element_by_id('report')
            soup = BeautifulSoup(driver.page_source, 'html.parser')
            riskLevel = soup.find('div', attrs={'class': 'scorebackgroundfilter numtitle'}).text.split()[0]
            if riskLevel != "Unknown":
                riskLevel = str(riskLevel) + " out of 10"
        except:
            riskLevel = C.NONE
            logging.exception(C.IBM + " - Screenshot")
        try:
            driver.save_screenshot(self.imageName.format(C.IBM))
            print(C.IBM + ": " + C.SS_SAVED)
            logging.info(C.IBM + " - Screenshot saved at " + self.imageName.format(C.IBM))
        except WebDriverException:
            logging.exception(C.IBM + " - Screenshot")
            print(C.IBM + ": " + C.SS_FAILED)
        finally:
            driver.quit()
            return riskLevel

    def urlscan(self, uuid):
        driver = webdriver.Chrome(executable_path=self.key.get("drive"), options=options)
        driver.get(C.URLSCAN_SS.format(uuid))
        try:
            element_present = EC.presence_of_element_located((By.CLASS_NAME, 'container'))
            WebDriverWait(driver, timeout).until(element_present)
            driver.save_screenshot(self.imageName.format(C.URLSCAN))
            saved = True
            logging.info(C.URLSCAN + " - Screenshot saved at " + self.imageName.format(C.URLSCAN))
        except WebDriverException:
            logging.exception(C.URLSCAN + " - Screenshot")
            saved = False
        finally:
            driver.quit()
            return saved


    def virusTotal(self, obj):
        driver = webdriver.Chrome(executable_path=self.key.get("drive"), options=options)
        driver.implicitly_wait(3)
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
            driver.find_element_by_tag_name('vt-virustotal-app')
            # element_present = EC.presence_of_element_located((By.TAG_NAME, 'vt-virustotal-app'))
            # WebDriverWait(driver, 1).until(element_present)
            ## To check scores are same with the VT API
            # root = str(driver.find_element_by_tag_name('vt-virustotal-app').text)
            # res = root.find("Community\nScore")
            # substr = root[res - 10:res - 1]
            # positives = int(''.join(list(filter(str.isdigit, substr.split("/")[0]))))
            # total = int(''.join(list(filter(str.isdigit, substr.split("/")[1]))))
            # rate = str(positives) + " out of " + str(total)
            # print(rate)
            driver.save_screenshot(self.imageName.format(C.VT))
            saved = True
            logging.info(C.VT + " - Screenshot saved at " + self.imageName.format(C.VT))
        except WebDriverException:
            logging.exception(C.VT + " - Screenshot")
            saved = False
        finally:
            driver.quit()
            return saved

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
            logging.info(C.CISCO + " - Screenshot saved at " + self.imageName.format(C.CISCO))
        except WebDriverException:
            web_reputation = C.NONE
            logging.exception(C.CISCO + " - Screenshot")
            print(C.CISCO + ": " + C.SS_FAILED)
            try:
                element_present = EC.presence_of_element_located((By.ID, 'cf-wrapper'))
                WebDriverWait(driver, timeout).until(element_present)
                print(C.CISCO + ": Please go to {} to check if captcha is required and complete it once"
                      .format(C.CISCO_SS + quote(iporurl)))
                logging.critical(C.CISCO + " - Recaptcha is required")
            except:
                pass
        finally:
            driver.quit()
            print(C.CISCO + ": " + web_reputation)
            logging.info(C.CISCO_SS + " - " + web_reputation)
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


