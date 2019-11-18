from requests import get
import requests.exceptions
from contextlib import closing
from bs4 import BeautifulSoup
import re
from pathlib import Path

GUARD_DUTY_URL = "https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html"
URL_PREFIX = "https://docs.aws.amazon.com/guardduty/latest/ug/"
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

# get the content of the guardduty_finding-types-active page, which contains the links to the various GuardDuty subcategories,
# and then get the get the category links themselves.... whichshould look something like this (as of Feb 2019)
# https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_backdoor.html
# https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_behavior.html
# https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_crypto.html
# https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_pentest.html
# https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_persistence.html
# https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_policy.html
# https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_recon.html
# https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_resource.html
# https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_stealth.html
# https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_trojan.html
# https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_unauthorized.html


"""
<div class="highlights">
    <p><strong>Topics</strong></p>
        <ul>
            <li><a href="guardduty_backdoor.html">Backdoor Finding Types</a></li>
            <li><a href="guardduty_behavior.html">Behavior Finding Types</a></li>
            <li><a href="guardduty_crypto.html">CryptoCurrency Finding Types</a></li>
            <li><a href="guardduty_pentest.html">PenTest Finding Types</a></li>
            <li><a href="guardduty_persistence.html">Persistence Finding Types</a></li>
            <li><a href="guardduty_policy.html">Policy Finding Types</a></li>
            <li><a href="guardduty_privilegeescalation.html">PrivilegeEscalation Finding
                    Types</a></li>
            <li><a href="guardduty_recon.html">Recon Finding Types</a></li>
            <li><a href="guardduty_resource.html">ResourceConsumption Finding Types</a></li>
            <li><a href="guardduty_stealth.html">Stealth Finding Types</a></li>
            <li><a href="guardduty_trojan.html">Trojan Finding Types</a></li>
            <li><a href="guardduty_unauthorized.html">Unauthorized Finding Types</a></li>
         </ul>
</div>
"""

html = get_webpage(GUARD_DUTY_URL)

if html['status']:

    # Souperize it beautifully
    soup = BeautifulSoup(html['data'].content, 'html.parser')
    # Get the Highlights div class, which inclusdes all the topics (see comments above)
    soup.find_all("div", class_="highlights")
    topics = []
    for div in soup.find_all("div", {"class":"highlights"}):
        for li in div.find_all('li'):
            a = li.find('a')
            topics.append(a['href'])

    # append the full URL to the topic
    topics_links = []
    for i in topics:
        i = URL_PREFIX + i
        topics_links.append(i)
            


    # Print to Lambda
    for i in topics_links:
        print(i)

else:
    # Exit if Requests returns an error
    
    raise SystemExit

# Loop through each link and get the findings
output = []
for i in topics_links:
    html = get_webpage(i)
    if html['status']:
        # Souperize it beautifully
        soup = BeautifulSoup(html['data'].content, 'html.parser')
        # get the topic titles from the list of topics under the "inline-topiclist" id
        inline_topiclist = soup.find(id="inline-topiclist").find_all('a', href=True)
        # this will extract the topic id ... eg unauthorized1
        # from <a href="#unauthorized1">UnauthorizedAccess:IAMUser/TorIPCaller</a>
        topics = (re.findall(r'(?<=#)[^\"]+', str(topic)) for topic in inline_topiclist)
        topics = [m[0] for m in topics if m]

        # Loop through the id's and search for them on the page
        # to pull out the relevent info
        for id in topics:
            print(f"processing {id}")
            finding = {}
            # eg. gets "EC2/TorRelay" from <h2 id="unauthorized14">UnauthorizedAccess:EC2/TorRelay</h2>
            finding['name'] = str(re.findall(r"(?<=:)[^<]+", str(soup.find(id=id)))[0]).strip()

            # eg. gets "UnauthorizedAccess" from <h2 id="unauthorized14">UnauthorizedAccess:EC2/TorRelay</h2>
            finding['category'] = str(re.findall(r"(?<=>)[^:]+", str(soup.find(id=id)))[0]).strip()

            # eg. gets "High" from <h3 id="unauthorized14_severity">Default severity: High</h3> 
            ## some have a hyphen rather than a underscore!! well, I say some, but only found one that I've come across so far - "<h3 id="ec2-metadatadnsrebind-severity">Default severity: High</h3>"
            # try underscore first
            try:
                id_severity = id + '_severity'
                finding['severity'] = str(re.findall(r"(?<=:)[^<]+", str(soup.find(id=id_severity)))[0]).strip()
            except IndexError:
                id_severity = id + '-severity'
                finding['severity'] = str(re.findall(r"(?<=:)[^<]+", str(soup.find(id=id_severity)))[0]).strip()

            # The next two get the summary and detail from the two <p>'s that follow <h3 id="unauthorized14_description">Finding description</h3>
            summary_text = str(soup.find(id=id).find_next('h3').find_next('p'))
            summary_text = summary_text.replace('\n', '')
            summary_text = ' '.join(summary_text.split())
            finding['summary'] = str(re.findall(r"(?<=>)[^<]+", summary_text)[0]).strip()

            detail_text = str(soup.find(id=id).find_next('h3').find_next('p').find_next('p'))
            detail_text = detail_text.replace('\n', '')
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

import csv 
csv_columns = ['name','category','severity','summary', 'detail']
with open('all_findings.csv', 'w') as csvfile:
    writer = csv.DictWriter(csvfile, fieldnames=csv_columns)
    writer.writeheader()
    for data in output:
        writer.writerow(data)

all_path = Path("all_findings.csv").resolve()

high_sev_findings = []
for o in output:
    if o['severity'] == 'High':
        high_sev_findings.append(o)
        
csv_columns = ['name','category','severity','summary', 'detail']
with open('high_findings.csv', 'w') as csvfile:
    writer = csv.DictWriter(csvfile, fieldnames=csv_columns)
    writer.writeheader()
    for data in high_sev_findings:
        writer.writerow(data)

high_path = Path("high_findings.csv").resolve()

print("***** DONE ***** \n\n")

print("******* The HIGH severity findings are below *******\n")
for i in high_sev_findings:
    print(f"|{i['severity']:<10}|{i['name']:<40}|{i['category']:<20}")

print(f"\nAll GuardDuty Findings have been saved to:           {str(all_path)}")
print(f"High Severity GuardDuty Findings have been saved to: {str(high_path)}\n\n")

