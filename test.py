import base64
import json
import sys
import time

import requests


def virusTotal(url):
    params = {
        'apikey': "",
        'resource': url
    }
    headers = {
        "Accept-Encoding": "gzip, deflate",
        "User-Agent": "gzip,  My Python requests library example client or username"
    }
    # https://www.virustotal.com/api/v3/urls/
    resp = requests.post("https://www.virustotal.com/vtapi/v2/url/report", params=params, headers=headers).json()
    if resp['response_code'] == 1:
        rate = str(resp['positives']) + " out of " + str(resp['total'])
    else:
        rate = "N/A"
    return rate


def virusTotal3(url):
    headers = {
        'x-apikey': "",
        'Accept': 'application/json'
    }
    # send url to scan
    resp = requests.post("https://www.virustotal.com/api/v3/urls/", headers=headers, data={'url': url})

    # fetch scan results
    encoded_url = base64.b64encode(url.encode())
    resp = requests.get(
        "https://www.virustotal.com/api/v3/urls/" + '{}'.format(encoded_url.decode().replace('=', '')),
        headers=headers)

    if resp.status_code == 200:
        # Check if the analysis is finished before returning the results
        # if 'last_analysis_results' key-value pair is empty, then it is not finised
        while not resp.json()['data']['attributes']['last_analysis_results']:
            resp = resp.get(
                "https://www.virustotal.com/api/v3/urls/" + '{}'.format(encoded_url.decode().replace('=', '')),
                headers=headers)
            time.sleep(3)
        print(resp.status_code)
        harmless = int(resp.json()['data']['attributes']['last_analysis_stats']['harmless'])
        malicious = int(resp.json()['data']['attributes']['last_analysis_stats']['malicious'])
        suspicious = int(resp.json()['data']['attributes']['last_analysis_stats']['suspicious'])
        timeout = int(resp.json()['data']['attributes']['last_analysis_stats']['timeout'])
        undetected = int(resp.json()['data']['attributes']['last_analysis_stats']['undetected'])
        rate = str(malicious + suspicious) + " out of " + str(malicious + harmless + suspicious + timeout + undetected)
    elif resp.status_code == 401:
        raise Exception("Error! Please verify API KEY!")
    elif resp.status_code == 429:
        raise Exception("Error! Requests Exceeded!")
    else:
        rate = str("Error " + str(resp.status_code) + ": " + str(resp))
    return rate


if __name__ == "__main__":
    file_to_read = sys.argv[2]
    print(file_to_read)
    file_data = open(file_to_read, 'r').read().split('\n')
    for url in file_data:
        if url == "":
            continue
        print("IN USE: " + url)
        try:
            vt = virusTotal3(url)
        except requests.exceptions.RequestException as error:
            print(str(error))
            vt = "N/A"
        except Exception as error:
            print(str(error))
            vt = "N/A"
        print("VirusTotal: " + vt)
