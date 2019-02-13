"""
gets the content of the guardduty_finding-types-active AWS GuardDuty Documentation webpage, 
which contains the links to the various GuardDuty subcategories,
and then get the get the category links themselves.... 
which should look something like this (as of Feb 2019)
https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_backdoor.html
https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_behavior.html
https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_crypto.html
https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_pentest.html
https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_persistence.html
https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_policy.html
https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_recon.html
https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_resource.html
https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_stealth.html
https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_trojan.html
https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_unauthorized.html 

GuardDuty naming convention
# CryptoCurrency:EC2/BitcoinTool.B!DNS
# ThreatPurpose:ResourceTypeAffected/ThreatFamilyName.ThreatFamilyVariant!Artifact
"""

from requests import get
import requests.exceptions
from bs4 import BeautifulSoup
import json
import re

GUARD_DUTY_URL = "https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html"
URL_PREFIX = "https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_"
FULL_URL_PREFIX = "https://docs.aws.amazon.com/guardduty/latest/ug/"

def get_webpage(url):
    data = {}
    try:
        response = get(url,timeout=3)
        response.raise_for_status()
    except requests.exceptions.HTTPError as err_http:
        data['status'] = False
        data['data'] = ("Requests:Http Error:", err_http)
    except requests.exceptions.ConnectionError as err_conn:
        data['status'] = False
        data['data'] = ("Requests:Connection Error:", err_conn)
    except requests.exceptions.Timeout as err_timeout:
        data['status'] = False
        data['data'] = ("Requests:Timeout Error:", err_timeout)
    except requests.exceptions.RequestException as err_other:
        data['status'] = False
        data['data'] = ("Requests:Undefined Error:", err_other)
    else:
        data['status'] = True
        data['data'] = (response)
    return data


def main(event, context):
    # Get the content of the GuardDuty Web Page
    html = get_webpage(GUARD_DUTY_URL)

    if html['status']:

        # Souperize it beautifully
        soup = BeautifulSoup(html['data'].content, 'html.parser')
        # Extract all the links ()
        findings_links = [a.get('href') for a in soup.find_all('a', attrs={'href': re.compile(URL_PREFIX)})]

        # Print to Lambda
        for i in findings_links:
            print(i)

    else:
        # Exit if Requests returns an error
        return {
        'statusCode': 200,
        'body': json.dumps(html['data']),
        'headers': {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Headers': 'Content-Type'
            }
        }

    # Loop through each link and get the findings
    output = []
    for i in findings_links:
        html = get_webpage(i)
        if html['status']:
            # Souperize it beautifully
            soup = BeautifulSoup(html['data'].content, 'html.parser')
            # get the topic titles from the list of topics under the "inline-topiclist" id
            inline_topiclist = soup.find(id="inline-topiclist").find_all('a', href=True)
            # this will extract the topic id ... eg unauthorized1
            # from <a href="#unauthorized1">UnauthorizedAccess:IAMUser/TorIPCaller</a>
            topics = [topic.attrs['href'].strip('#') for  topic in inline_topiclist]

            # Loop through the id's and search for them on the page
            # to pull out the relevent info
            for id in topics:
                print(f"processing {id}")
                finding = {}
                # eg. gets "TorRelay" from <h2 id="unauthorized14">UnauthorizedAccess:EC2/TorRelay</h2>
                finding['ThreatFamilyName'] = soup.find(id=id).text.split("/")[-1]

                # eg. gets "EC2" from <h2 id="unauthorized14">UnauthorizedAccess:EC2/TorRelay</h2>
                finding['ResourceTypeAffected'] = soup.find(id=id).text.split("/")[0].split(":")[-1]

                # eg. gets "UnauthorizedAccess" from <h2 id="unauthorized14">UnauthorizedAccess:EC2/TorRelay</h2>
                finding['ThreatPurpose'] = soup.find(id=id).text.split("/")[0].split(":")[0]

                # eg. gets "High" from <h3 id="unauthorized14_severity">Default severity: High</h3> 
                finding['Severity'] = soup.find(id=id).find_next('h3').text.split(":")[-1].strip()

                # The next two get the summary and detail from the two <p>'s that follow <h3 id="unauthorized14_description">Finding description</h3>
                summary_text = soup.find(id=id).find_next('h3').find_next('p').text.replace('\n', '')
                finding['summary'] = ' '.join(summary_text.split())
        
                detail_text = soup.find(id=id).find_next('h3').find_next('p').find_next('p').text.replace('\n', '')
                detail_text = ' '.join(detail_text.split())
                detail_text = detail_text.replace('<p>', '')
                detail_text = detail_text.replace('</p>', '').strip()
                # replace the relatrive link in the detail with the full URL
                if "<a href" in detail_text:
                    relative_href = str(re.findall(r"(?<=\")[^#]+", detail_text)[0])
                    full_url = FULL_URL_PREFIX + relative_href
                    detail_text = detail_text.replace(relative_href, full_url)
                finding['detail'] = detail_text

                output.append(finding)
        else:
            print(f"****ERROR****: {i}")
            print(html['data'])

    return {
    'statusCode': 200,
    'body': json.dumps(output),
    'headers': {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'Content-Type'
        }
    }
