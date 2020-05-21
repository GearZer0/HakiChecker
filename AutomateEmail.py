# -*- coding: utf-8 -*-
from pathlib import Path
import pywintypes
import xlrd
import win32com.client
from datetime import datetime
import re
import subprocess
import os
from time import sleep

template = {}


def init():
    with open("emailTemplate.txt") as f:
        for line in f:
            if line != "\n" and not line.startswith('['):
                (k, val) = line.split("=", 1)
                template[k.strip()] = val.strip()


def downloadAttach():
    outlook = win32com.client.Dispatch("Outlook.Application").GetNamespace("MAPI")
    try:
        inbox = outlook.Folders(template.get("mailbox_name")).Folders.Item("Inbox")
    except pywintypes.com_error:
        print("Error: mailbox_name defined in emailTemplate.txt does not exists")
        quit()
    today = datetime.now().strftime("%d %B %Y")
    target_name = "SP Daily Summary Report {}".format(today)
    if template.get("target_email_subject"):
        target_name = template.get("target_email_subject")
    filter_cond = ("@SQL=" + chr(34) + "urn:schemas:httpmail:subject" +
              chr(34) + " Like '" + "%" + target_name + "' AND " +
              chr(34) + "urn:schemas:httpmail:hasattachment" +
              chr(34) + "=1")

    items = inbox.Items.Restrict(filter_cond)
    if len(items):
        print("Found email: " + target_name)
        for item in items:
            for attachment in item.Attachments:
                print("Downloading attachment " + attachment.FileName)
                attachment.SaveAsFile(os.getcwd() + "/" + attachment.FileName)
                return attachment.FileName
        print("Error: {} email does not have any attachment".format(target_name))
        quit()
    else:
        print("Error: No email subject found with the name: " + target_name)
        quit()


def sendEmail(filename):
    outlook = win32com.client.Dispatch('outlook.application')
    mail = outlook.CreateItem(0)
    mail.To = template.get("recipient_email")
    mail.Subject = template.get("email_subject")
    mail.Body = template.get("email_body")
    #   mail.HTMLBody = '<h2>HTML Message body</h2>' #this field is optional

    # Attach a file to email
    attachment = filename
    mail.Attachments.Add(attachment)

    mail.SentOnBehalfOfName = template.get("your_email")
    mail.Send()
    print("Email sent to " + template.get("recipient_email"))


if __name__ == "__main__":
    try:
        init()
        file_name = downloadAttach()
        wb = xlrd.open_workbook(file_name)
        sheet = wb.sheet_by_index(0)
        all_ips = []
        for i in range(sheet.nrows):
            cell_data = sheet.cell_value(i, 4)
            ip_found = re.findall('[\d]+.[\d]+.[\d]+.[\d]+', cell_data)
            if len(ip_found):
                all_ips.append(ip_found[0])
        with open('tmp.txt', 'a+') as ip_file:
            for ip in all_ips:
                ip_file.write(str(ip) + "\n")
        print("Running HakiChecker ... please wait for output to populate shortly ...")
        run_bot = subprocess.Popen('python HakiChecker.py -ip tmp.txt'.split(' ')).wait()
        files = sorted(os.listdir('Results'), key=lambda x: os.path.getctime(os.path.join(os.getcwd(), "Results")))
        print(files)
        try:
            sendEmail(os.getcwd() + "/Results/" + files[-1])
        except:
            print("Error: Email failed to send to " + template.get("recipient_email"))
    except:
        print("Error encountered")
    finally:
        # Remove files created
        if os.path.exists("tmp.txt"):
            os.remove("tmp.txt")
        if os.path.exists(file_name):
            os.remove(file_name)
