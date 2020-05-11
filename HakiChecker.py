# -*- coding: utf8 -*-
import hashlib
import requests
import json
import base64
import csv
import sys
import os
from time import sleep, time
from urllib.parse import quote
import logging
from requests.auth import HTTPBasicAuth
from validator_collection import validators
from validator_collection.errors import *

import Constant as C
import Screenshot

# Specify where the output files should be stored in.
output_directory = os.getcwd() + "/Results/"
image_directory = os.getcwd() + "/Images/"

# Constants that needs to be updated in init()
vt_headers = {'Accept': 'application/json'}
ibm_headers = {"Content-Type": "application/json"}
key = {}

# Initialisation of modes
mode = C.NONE
ss_mode = False
single_mode = False


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



# function to save result in csv file
def save_record(data, formula):
    logging.info("Saving Record of {mode}: {target}".format(mode=mode, target=data[0]))
    if formula == C.IP_MODE:
        fieldnames = ["Target", C.IBM, C.VT, C.ABIP, C.FG, C.AUTH0, "Action"]
        if ss_mode:
            fieldnames.insert(len(fieldnames)-1, C.CISCO)
        with open(output_directory + C.SAVE_IP, mode="a+", encoding="utf-8", newline="") as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
            if os.stat(output_directory + C.SAVE_IP).st_size == 0:
                writer.writeheader()
            malic = "Safe"
            nonzero = 0
            if not data[1].startswith("1 out") and data[1] != C.NONE:
                nonzero += 1
            if not data[2].startswith("0 out") and data[2] != C.NONE:
                nonzero += 1
            if not data[3].startswith("0 out") and data[3] != C.NONE:
                nonzero += 1
            if not data[4].startswith("1 out") and data[4] != C.NONE:
                nonzero += 1
            if data[5] != "0" and data[5] != C.NONE:
                nonzero += 1
            if ss_mode and (data[6] == "Questionable" or data[6] == "Untrusted"):
                nonzero += 1
            if nonzero > 0:
                malic = "To Block"

            if ss_mode:
                writer.writerow({"Target": data[0], C.IBM: data[1], C.VT: data[2], C.ABIP: data[3],
                                 C.FG: data[4], C.AUTH0: data[5], C.CISCO: data[6], "Action": malic})
            else:
                writer.writerow({"Target": data[0], C.IBM: data[1], C.VT: data[2], C.ABIP: data[3],
                                 C.FG: data[4], C.AUTH0: data[5], "Action": malic})
    elif formula == C.URL_MODE:
        fieldnames = ["Target", C.IBM, C.VT, C.GOOGLE, C.PHISH, "Action"]
        if ss_mode:
            fieldnames[5:5] = [C.URLSCAN, C.URLSCAN + "UUID", C.CISCO]
        with open(output_directory + C.SAVE_URL, mode="a+", encoding="utf-8", newline="") as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
            if os.stat(output_directory + C.SAVE_URL).st_size == 0:
                writer.writeheader()
            malic = "Safe"
            nonzero = 0
            if not data[1].startswith("1 out") and data[1] != C.NONE:  # IBM
                nonzero += 1
            if not data[2].startswith("0 out") and data[2] != C.NONE:  # VT
                nonzero += 1
            if not data[3].startswith("Safe") and data[4] != C.NONE:  # Google
                nonzero += 1
            if data[4] and data[4] != C.NONE:  # PhishTank
                nonzero += 1
            if ss_mode and not data[5].startswith("0 out") and data[5] != C.NONE:  # URLscan
                nonzero += 1
            if ss_mode and (data[7] == "Questionable" or data[6] == "Untrusted"):  # CiscoTalos
                nonzero += 1
            if nonzero > 0:
                malic = "To Block"

            if ss_mode:
                writer.writerow(
                    {"Target": data[0], C.IBM: data[1], C.VT: data[2], C.GOOGLE: data[3],
                     C.PHISH: data[4], C.URLSCAN: data[5], C.URLSCAN + "UUID": data[6],
                     C.CISCO: data[7], "Action": malic})
            else:
                writer.writerow(
                    {"Target": data[0], C.IBM: data[1], C.VT: data[2], C.GOOGLE: data[3],
                     C.PHISH: data[4], "Action": malic})
    elif formula == C.FILE_MODE:
        fieldnames = ["Target", C.VT]
        with open(output_directory + C.SAVE_FILE, mode="a+", encoding="utf-8", newline="") as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
            if os.stat(output_directory + C.SAVE_FILE).st_size == 0:
                writer.writeheader()
            writer.writerow({"Target": data[0], C.VT: data[1]})
    elif formula == C.HASH_MODE:
        fieldnames = ["Target", "MD5", "SHA256", "SHA1", "Score"]
        with open(output_directory + C.SAVE_HASH, mode="a+", encoding="utf-8", newline="") as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
            if os.stat(output_directory + C.SAVE_HASH).st_size == 0:
                writer.writeheader()
            writer.writerow({"Target": data[0], "MD5": data[1], "SHA256": data[2], "SHA1": data[3], "Score": data[4]})


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


def virusTotalFile(file):
    with open(file, 'rb') as f:
        data = {'file': f.read()}
    # upload file based on size
    file_size = os.path.getsize(file)
    try:
        if file_size <= 33554432:
            resp = requests.post(C.VT_FILE, headers=vt_headers, files=data)
        else:  # bigger than 32 mb - there may be performance issue as a file gets too big
            resp = requests.get(C.VT_FILE_BIG, headers=vt_headers)
            vt_exception(resp)
            upload_url = resp.json()['data']
            resp = requests.post(upload_url, headers=vt_headers, files=data)
        vt_exception(resp)
    except Exception as e:
        vt = C.NONE
        logging.exception(C.VT + " - " + str(e))
    else:
        vt = vt_result(resp)
        filehash = str(getmd5(file))
        # retrieve analysis
        vt = virusTotalHash([filehash, file])[4]
    finally:
        print(C.VT + ": " + vt)
        logging.info(C.VT + " - " + vt)
        return vt


def virusTotalHash(a_hash):
    vt_screenshot(a_hash)
    if mode == C.FILE_MODE:
        a_hash = a_hash[0]
    try:
        resp = requests.get(C.VT_FILE + '/{}'.format(a_hash), headers=vt_headers)
        vt_exception(resp)
    except Exception as e:
        vt = C.NONE
        logging.exception(C.VT + " - " + str(e))
    else:
        # Status: confirmed-timeout, failure, harmless, malicious, suspicious, timeout, type-unsupported, undetected
        vt = vt_result(resp)
    finally:
        print(C.VT + ": " + str(vt))
        logging.info(C.VT + " - " + vt)

    try:
        md5 = resp.json()['data']['attributes']['md5']
        sha256 = resp.json()['data']['attributes']['sha256']
        sha1 = resp.json()['data']['attributes']['sha1']
    except (KeyError, TypeError) as e:
        logging.error(C.VT + " - virusTotalHash() - " + str(e))
        md5 = C.NONE
        sha256 = C.NONE
        sha1 = C.NONE
    finally:
        data = [a_hash, md5, sha256, sha1, vt]
        return data



# only works for url, no ip support
def abusedIP(ip):
    if ss_mode:
        if ss.abusedIP(ip):
            print(C.ABIP + ": " + C.SS_SAVED)
        else:
            print(C.ABIP + ": " + C.SS_FAILED)
    headers = {
        'Key': key.get("abip_key"),
        'Accept': 'application/json',
    }
    params = {'ipAddress': ip }
    try:
        resp = json.loads(requests.get(C.ABIP_IP, headers=headers, params=params).text)
        rate = str(resp['data']["abuseConfidenceScore"]) + " out of 100"
    except:
        rate = C.NONE
        error = resp['errors']
        if error[0]['status'] == 429 or error[0]['status'] == 401:
            print(C.ABIP + ": " + error[0]['detail'])
        elif str(error[0]['status']).startswith('5'):
            print(C.ABIP + ": AbusedIPDB is having problems. Please try again later")
        logging.error(C.ABIP + " - virusTotalHash() - " + error[0]['detail'])
    finally:
        print(C.ABIP + ": " + rate)
        logging.info(C.ABIP + " - " + rate)
        return rate


def getScreenshotIBM(obj):
    rate = ss.IBM(obj)
    if rate == "Unknown":
        rate = C.NONE
    else:
        rate + " out of 10"
    logging.info(C.IBM + " - " + rate)
    return rate


# call to this function when url mode on
def IBM_URL(url):
    if ss_mode:
        return getScreenshotIBM(url)
    else:
        try:
            resp = requests.get(C.IBM_URL.format(quote(url)), headers=ibm_headers)
            rate = str(resp.json()['result']['score']) + " out of 10"
        except:
            rate = C.NONE
            logging.error(C.IBM + " - " + str(resp.json()))
            if resp.status_code == 402:
                print(C.IBM + ": Monthly quota exceeded")
            elif resp.status_code == 401:
                print(C.IBM + ": Not Authorized. Check API key and pass")
            elif str(resp.status_code).startswith('5'):
                print(C.IBM + ": IBM is having problems. Please try again later")
        finally:
            print(C.IBM + ": " + rate)
            logging.info(C.IBM + " - " + rate)
            return rate


# call to this function when ip mode on
def IBM_IP(ip):
    if ss_mode:
        return getScreenshotIBM(ip)
    else:
        try:
            resp = requests.get(C.IBM_IP.format(ip), headers=ibm_headers)
            rate = str(resp.json()['history'][-1]['score']) + " out of 10"
        except:
            rate = C.NONE
            logging.error(C.IBM + " - " + str(resp.json()))
            if resp.status_code == 402:
                print(C.IBM + ": Monthly quota exceeded")
            elif resp.status_code == 401:
                print(C.IBM + ": Unauthorized. Check API key and pass")
            elif str(resp.status_code).startswith('5'):
                print(C.IBM + ": IBM is having problems. Please try again later")
        finally:
            print(C.IBM + ": " + rate)
            logging.info(C.IBM + " - " + rate)
            return rate


def getFGKey():
    keys = open(C.FG_KEYS, 'r').read().split('\n')
    if keys == "":
        print("Are you sure about FG Keys availability?")
    return keys[0]


def removeOldFGKey(get_key):
    keys = open(C.FG_KEYS, 'r').read().split('\n')
    open(C.FG_KEYS, 'w+').close()
    with open(C.FG_KEYS, 'a+') as fl:
        for i in keys:
            if i != get_key:
                fl.write(i + "\n")
        fl.write(get_key + "\n")


def fraudGuard(ip):
    if ss_mode:
        if ss.fraudguard(ip):
            print(C.FG + ": " + C.SS_SAVED)
        else:
            print(C.FG + ": " + C.SS_FAILED)
    get_key = getFGKey()
    username = get_key.split(':')[0]
    password = get_key.split(':')[1]
    resp = requests.get(C.FG_IP.format(ip), verify=True, auth=HTTPBasicAuth(username, password))
    if resp.status_code == 429:
        print("API limit reached, changing username:password")
        removeOldFGKey(get_key)
        return fraudGuard(ip)
    try:
        rate = json.loads(resp.text)['risk_level'] + " out of 5"
    except:
        rate = C.NONE
        logging.error(C.FG + " - " + str(resp.text))
        if resp.status_code == 401:
            print(C.FG + ": Unauthorised. Check credentials")
        if str(resp.status_code).startswith('5'):
            print(C.FG + ": FraudGaurd is having problems. Please try again later")
    finally:
        print(C.FG + ": " + rate)
        logging.info(C.FG + " - " + rate)
        return rate


def urlscan(url):
    headers = {"API-Key": key.get("urlscan_key")}
    data = {"url": url}
    try:
        # send scan request
        resp = requests.post(C.URLSCAN_URL, data=data, headers=headers)
        uuid = resp.json()['uuid']
        nextpage = resp.json()['api']
    except:
        score = C.NONE
        uuid = C.NONE
        logging.exception(C.URLSCAN + " - " + str(resp.json()))
        if resp.status_code == 401:
            print(C.URLSCAN + ": Unauthorized. Check API key")
    else:
        begin = time()
        time_elapsed = 0
        result = requests.get(nextpage)
        # repeat until url has finished scanning. Max time is 65seconds
        while result.status_code == 404 and time_elapsed < 65:
            sleep(5)
            result = requests.get(nextpage)
            time_elapsed = time() - begin
        try:
            score = str(result.json()['verdicts']['overall']['score']) + " out of 100"
        except:
            score = C.NONE
            logging.exception(C.URLSCAN + " - " + str(result.json()))
        finally:
            with open(ss.imageName.format(""), "wb+") as img_sc:
                try:
                    img_sc.write(requests.get(C.URLSCAN_SS_ORIGIN + uuid + ".png").content)
                    print(C.URLSCAN + ": Screenshot of target URL saved")
                except:
                    print(C.URLSCAN + ": Failed to save screenshot of target URL")
            if ss.urlscan(uuid):
                print(C.URLSCAN + ": " + C.SS_SAVED)
            else:
                print(C.URLSCAN + ": " + C.SS_FAILED)
    finally:
        print(C.URLSCAN + ": " + score)
        logging.info(C.URLSCAN + " - " + score)
        return [str(score), uuid]


def googleSafe(url):
    if ss_mode:
        if ss.googleSafe(url):
            print(C.GOOGLE + ": " + C.SS_SAVED)
        else:
            print(C.GOOGLE + ": " + C.SS_FAILED)
    data = {
        "client": {"clientId": "ProjectAuto", "clientVersion": "1.5.2"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "THREAT_TYPE_UNSPECIFIED", "UNWANTED_SOFTWARE",
                            "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["WINDOWS"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]}}
    resp = requests.post(C.GOOGLE_URL + key.get("google_key"), data=json.dumps(data))
    if resp.status_code == 200:
        if "matches" in resp.json().keys():
            gsb = resp.json()["matches"][0]["threatType"]
        else:
            gsb = "Safe"
    else:
        gsb = C.NONE
        if resp.status_code == 429:
            print(C.GOOGLE + ": Requests Exceeded!")
        elif str(resp.status_code).startswith('5'):
            print(C.GOOGLE + C.EX_SERVER.format(C.GOOGLE))
        logging.error(C.GOOGLE + " - " + str(resp.json()))
    print(C.GOOGLE + ": " + gsb)
    logging.info(C.GOOGLE + " - " + gsb)


def auth0(ip):
    if ss_mode:
        if ss.auth0(ip):
            print(C.AUTH0 + ": " + C.SS_SAVED)
        else:
            print(C.AUTH0 + ": " + C.SS_FAILED)
    headers = {
        "Accept": "application/json",
        "X-Auth-Token": key.get("auth0_key")
    }
    resp = requests.get(C.AUTH0_IP.format(ip), headers=headers).json()
    return str(resp['fullip']['score']).strip()


# def hybrid(url):
#     data = {
#         'scan_type': 'all',
#         'url': url
#     }
#     headers = {
#         'api-key': key.get("hybrid_key"),
#         'user-agent': 'Falcon Sandbox'
#     }
#     resp = requests.post(C.HYBRID_IP, data=data, headers=headers).json()
#     report_id = resp['sha256']
#     resp2 = requests.get("https://www.hybrid-analysis.com/api/v2/report/{}/summary".format(report_id),
#                          headers=headers).json()
#     with open("images_hybrid/" + report_id + ".png", "wb+") as img_sc:
#         try:
#             img_sc.write(requests.get("https://www.hybrid-analysis.com/api/v2/report/" + report_id + "/screenshots",
#                                       headers=headers).content)
#         except:
#             pass
#     return resp2['threat_level']


def phishtank(url):
    if ss_mode:
        if ss.phishtank(url):
            print(C.PHISH + ": " + C.SS_SAVED)
        else:
            print(C.PHISH + ": " + C.SS_FAILED)
    data = {
        "url": url,
        'format': "json",
        'app_key': key.get("phish_key")
    }
    headers = {
        "User-Agent": "phishtank/" + key.get("phish_user")
    }
    resp = requests.post(C.PHISH_URL, headers=headers, data=data)
    if resp.status_code == 509:
        raise Exception("ERROR: Requests Exceeded! Please wait at most 5 minutes to reset the number of requests.")
    elif resp.status_code != 200:
        raise Exception("")

    if resp.json()['results']['in_database']:  # if it exists in database
        if not resp.json()['results']['verified']:  # if pending verification return malicious
            return "Questionable"
        elif resp.json()['results']['verified'] and resp.json()['results']['valid']:  # if phish return malicious
            return "Phish"
        else:  # if verified as not a phish
            return False
    return False  # if not in database

def isIP(ip):
    if ip == "":
        return False
    logging.info("---------- Checking " + ip + " ----------")
    try:
        validators.ip_address(ip)
        return True
    except InvalidIPAddressError as e:
        print(e)
        logging.error(e)
        return False


def isURL(url):
    if url == "":
        return False
    logging.info("---------- Checking " + url + " ----------")
    try:
        validators.url(url)
        return True
    except InvalidURLError as e:
        print(e)
        logging.error(e)
        return False


def isFile(file):
    if file == "":
        return False
    logging.info("---------- Checking " + file + " ----------")
    if not os.path.isfile(file):
        print('File not found. Please submit a valid file path')
        logging.error("Invalid File path")
        return False
    else:
        return True


def ipmode(ip):
    print("---------------------------------------\n" + ip + "\n---------------------------------------")
    vt = virusTotalIP(ip)
    abip = abusedIP(ip)
    fg = fraudGuard(ip)
    ibm_rec = IBM_IP(ip)
    try:
        ath0 = auth0(ip)
    except:
        ath0 = C.NONE
    print(C.AUTH0 + ": " + str(ath0))
    if ss_mode:
        try:
            ct = ss.ciscoTalos(ip)
        except Exception as e:
            logging.error(e)
            ct = C.NONE
        print(C.CISCO + ": " + ct)
    data = [ip, ibm_rec, vt, abip, fg, ath0]
    if ss_mode:
        data.append(ct)
    return data


def urlmode(url):
    print("---------------------------------------\n" + url + "\n---------------------------------------")
    vt = virusTotalURL(url)
    ibm_rec = IBM_URL(url)
    gsb = googleSafe(url)
    try:
        pt = phishtank(url)
    except Exception as error:
        if str(error) != "":
            print(str(error))
        pt = C.NONE
    except:
        pt = C.NONE
    print(C.PHISH + ": " + str(pt))
    if ss_mode:
        usc = urlscan(url)
        uscuuid = usc[1]
        usc = usc[0]
        try:
            ct = ss.ciscoTalos(url)
        except Exception as e:
            logging.error(e)
            ct = C.NONE
        print(C.CISCO + ": " + ct)
    data = [url, ibm_rec, vt, gsb, pt]
    if ss_mode:
        data.append(usc)
        data.append(uscuuid)
        data.append(ct)
    return data


def hashmode(a_hash):
    print("---------------------------------------\nChecking:   " + a_hash)
    return virusTotalHash(a_hash)


def filemode(a_file):
    print("---------------------------------------\nChecking:   " + a_file)
    vt = virusTotalFile(a_file)
    data = [a_file, vt]
    return data


def helptext():
    # Help
    print("Wrong Syntax. Please refer below for correct syntax.")
    print("Usage: " + sys.argv[0] + " -sip xx.xx.xx.xx")
    print("Usage: " + sys.argv[0] + " -ip list.txt")
    print("Usage: " + sys.argv[0] + " -surl xxxxxx")
    print("Usage: " + sys.argv[0] + " -surl xxxxxx -ss")
    print("Usage: " + sys.argv[0] + " -url list.txt")
    print("Usage: " + sys.argv[0] + " -url list.txt -ss")
    print("Usage: " + sys.argv[0] + " -shash xxxxx")
    print("Usage: " + sys.argv[0] + " -hash list.txt")
    print("Usage: " + sys.argv[0] + " -file list.txt")


if __name__ == "__main__":
    start = time()
    init()  # initialisation

    if len(sys.argv) == 3 or (len(sys.argv) == 4 and sys.argv[3] == "-ss"):
        file_to_read = sys.argv[2]
        if sys.argv[1] == "-url":
            mode = C.URL_MODE
        elif sys.argv[1] == "-ip":
            mode = C.IP_MODE
        elif sys.argv[1] == "-file":
            mode = C.FILE_MODE
        elif sys.argv[1] == "-hash":
            mode = C.HASH_MODE
        elif sys.argv[1] == "-shash":
            mode = C.HASH_MODE
        elif sys.argv[1] == "-sip":
            mode = C.IP_MODE
        elif sys.argv[1] == "-surl":
            mode = C.URL_MODE
        else:  # Incorrect command line arg
            helptext()
            exit()

        # Check for single mode and screenshot mode
        if '-s' in sys.argv[1]:
            single_mode = True
        if len(sys.argv) == 4 and sys.argv[3] == "-ss":
            ss_mode = True
            ss = Screenshot.Screenshot(mode, key)

        if single_mode:
            if ss_mode:
                ss.makeFileName(file_to_read)
            if mode == C.IP_MODE:
                if isIP(file_to_read):
                    ipmode(file_to_read)
            elif mode == C.URL_MODE:
                if isURL(file_to_read):
                    urlmode(file_to_read)
            elif mode == C.HASH_MODE:
                res = hashmode(file_to_read)
                print("md5: " + res[1])
                print("sha256: " + res[2])
                print("sha1: " + res[3])

        else:  # multiple mode
            file_data = open(file_to_read, 'r').read().split('\n')
            if mode == C.IP_MODE:
                for addr in file_data:
                    if not isIP(addr):
                        continue
                    if ss_mode:
                        ss.makeFileName(addr)
                    dataset = ipmode(addr)
                    save_record(dataset, C.IP_MODE)
            elif mode == C.URL_MODE:
                for link in file_data:
                    if not isURL(link):
                        continue
                    if ss_mode:
                        ss.makeFileName(link)
                    dataset = urlmode(link)
                    save_record(dataset, C.URL_MODE)
            elif mode == C.FILE_MODE:
                for f in file_data:
                    startFileTime = time()
                    if not isFile(f):
                        continue
                    dataset = filemode(f)
                    save_record(dataset, C.FILE_MODE)
                    print("Time Taken: " + str(round(time() - startFileTime, 2)))
            elif mode == C.HASH_MODE:
                for h in file_data:
                    if h == "":
                        continue
                    if ss_mode:
                        ss.makeFileName(h)
                    dataset = hashmode(h)
                    save_record(dataset, C.HASH_MODE)

            print("---------------------------------------\nTotal Time Elapsed: " + str(round(time() - start, 2)))

    else:  # Incorrect command line arg
        helptext()
        exit()
