''' Firewall Audit - postaudit.py

Copyright 2024 Sophos Ltd.  All rights reserved.
Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing
permissions and limitations under the License.

The purpose of this script is to upload the results to S3 and email a link to the results.

Tasks:
- Zip the results folder and upload to an S3 bucket
- Check `results.json` for audit failures, and if found, send email to the network team alias with link to the zip file on the S3 bucket.

Environment Variables (Required):
SMTP_USERNAME = SMTP Server Username
SMTP_PASSWORD = SMTP Server Password
SMTP_SERVER_PORT = SMTP Server Port
SMTP_SERVER = SMTP Server Hostname
SMTP_SENDER = SMTP Sender Email
SMTP_RECIPIENT = SMTP Recipient Email
S3_BUCKET = S3 Bucket name

'''
import os
import logging
import json
import glob
import shutil
import boto3
import smtplib
from prettytable import PrettyTable, ALL
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from rich.logging import RichHandler
from jinja2 import Environment, PackageLoader, select_autoescape

FORMAT = '%(message)s'
logging.basicConfig(level=logging.INFO, format=FORMAT, handlers=[RichHandler(show_path=False,
                                                                             omit_repeated_times=False)])

env = Environment(
        loader=PackageLoader("postaudit"),
        autoescape=select_autoescape()
    )  

def zip_results(dir_name):
    """Zip the results file and return the filename

    Args:
        dir_name (str): Directory to Zip

    Returns:
        str: Zip file name
    """
    return shutil.make_archive(f"{dir_name}", "zip", base_dir=dir_name)
    

def upload_to_s3(bucket_name, file_name):
    """Upload a file to an S3 bucket

    Args:
        bucket_name (str): S3 bucket name
        file_name (str): File name
    """
    client = boto3.client('s3')
    logging.info(f"Uploading {file_name} to S3 bucket {bucket_name}")
    client.upload_file(Bucket=bucket_name, Filename=file_name, Key=file_name)
    url = client.generate_presigned_url('get_object',
                                         Params={'Bucket': bucket_name, 'Key': file_name}, ExpiresIn=604800)
    return url

def send_email(msg_subject, msg_body, recipient):
    """Send email notification.

    Args:
        msg_subject (str): Message Subject
        msg_body (str): Message body
    """
    try:
        username = os.environ['SMTP_USERNAME']
        pwd = os.environ['SMTP_PASSWORD']
        port = os.environ['SMTP_SERVER_PORT']
        smtp_server = os.environ['SMTP_SERVER']
        sender_email = os.environ['SMTP_SENDER']
        recipient_email = recipient
        conn = smtplib.SMTP_SSL(smtp_server, port)
        conn.login(username, pwd)
        email_msg = MIMEMultipart("alternative")
        email_msg["From"] = sender_email
        email_msg["To"] = recipient_email
        message_body = f"""\
            <html>
                <body>
                <p>
                {msg_body}<br>
                <br>
                </p>
                </body>
            </html>
        """
        email_msg["Subject"] = msg_subject
        email_msg.attach(MIMEText(message_body, "html"))
        conn.sendmail(sender_email, recipient_email, email_msg.as_string())
        conn.close()
        logging.info("Email Delivered Successfully.")
    except Exception as e:
        logging.error(f"Error sending email: {e}")

def parse_results(results):
    """Parse the results file and return a table

    Args:
        results (str): HTML table listing hosts and audit result

    Returns:
        _type_: _description_
    """
    table = PrettyTable()
    table.hrules = ALL
    table.field_names = ["Hostname", "Passed", "Failed"]
    
    for firewall in results:
        table.add_row([firewall, results[firewall]["success_ct"], results[firewall]["failed_ct"]])
    table.align["Hostname"] = "l"
    html_table = table.get_html_string(format=True)
    return html_table
        

if __name__ == "__main__":
    dir_name = glob.glob("audit-results*")[0]
    filename = zip_results(dir_name)

    S3_BUCKET = os.environ["S3_BUCKET"]

    logging.info(f"Uploading file {filename} to S3 bucket {S3_BUCKET}")
    s3_url = upload_to_s3(S3_BUCKET, filename)

    with open("results.json", "r", encoding="utf-8") as fn:
        results = json.loads(fn.read())

    html_table = parse_results(results)

    msg_subject = "Firewall Audit Report"
    template = env.get_template("email_body.j2")
    msg_body = template.render(filename=filename,
                                html_table=html_table,
                                s3_url=s3_url)
    logging.info("Sending email...")    
    send_email(msg_subject, msg_body, os.environ["SMTP_RECIPIENT"])

    logging.info("Post audit tasks completed successfully!")
    

