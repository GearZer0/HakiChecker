# -*- coding: utf-8 -*-
import xlrd
import win32com.client
from datetime import datetime
import re
import subprocess
import os
from time import sleep

key = {}


def init():
    with open("emailTemplate.txt") as f:
        for line in f:
            if line != "\n" and not line.startswith('['):
                (k, val) = line.split("=", 1)
                key[k.strip()] = val.strip()


def downloadAttach():
    Outlook = win32com.client.Dispatch("Outlook.Application").GetNamespace("MAPI")
    Inbox = Outlook.Folders("***REMOVED***").Folders.Item("Inbox")
    today = datetime.now().strftime("%d %B %Y")
    file_name = "%SP Daily Summary Report  "
    Filter = ("@SQL=" + chr(34) + "urn:schemas:httpmail:subject" +
              chr(34) + " Like '" + file_name + "' AND " +
              chr(34) + "urn:schemas:httpmail:hasattachment" +
              chr(34) + "=1")

    items = Inbox.Items.Restrict(Filter)
    for item in items:
        for attachment in item.Attachments:
            print(attachment.FileName)
            attachment.SaveAsFile(os.getcwd() + "/" + attachment.FileName)
            return attachment.FileName


def sendEmail(filename):
    outlook = win32com.client.Dispatch('outlook.application')
    mail = outlook.CreateItem(0)
    mail.To = '***REMOVED***'
    mail.Subject = 'test'
    mail.Body = 'Hello, \nHehe'
    #   mail.HTMLBody = '<h2>HTML Message body</h2>' #this field is optional

    # To attach a file to the email (optional):
    attachment = filename
    mail.Attachments.Add(attachment)

    mail.SentOnBehalfOfName = '***REMOVED***'
    mail.Send()
    print("Email sent ...")


if __name__ == "__main__":
    print("Downloading attachment")

    # today = datetime.now().strftime("%Y%m%d")
    file_name = downloadAttach()
    wb = xlrd.open_workbook(file_name)
    sheet = wb.sheet_by_index(0)
    all_ips = []
    for i in range(sheet.nrows):
        cell_data = sheet.cell_value(i, 4)
        IP = re.findall('[\d]+.[\d]+.[\d]+.[\d]+', cell_data)
        if len(IP):
            IP = IP[0]
            all_ips.append(IP)
    all_ips = list(set(all_ips))
    if os.path.exists("tmp.txt"):
        os.remove("tmp.txt")
    with open('tmp.txt', 'a+') as ip_file:
        ip_file.write("156.255.30.244")
        # for ip in all_ips:
        #     ip_file.write(ip + "\n")
    print("Running command ... please wait for output to populate shortly ...")
    run_bot = subprocess.Popen('python HakiChecker.py -ip tmp.txt'.split(' ')).wait()
    while True:
        sleep(1)
        files = os.listdir("Results")
        if len(files) > 0:
            # files = sorted(filter(os.path.isfile, os.listdir('Results')), key=os.path.getmtime)
            sendEmail(os.getcwd() + "/Results/" + files[0])
            break
