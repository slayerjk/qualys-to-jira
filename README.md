=====Qualys Report to Jira Ticket=====

====Requirements====

  * Your Jira API user must have rights to create Tasks and Subtasks in your Jira Project.
  * Python3 required(written on Python 3.10.4).

Python modules required:
  * logging
  * datetime
  * time
  * os
  * sys
  * requests
  * xml.etree.ElementTree
  * json
  * re
  * tarfile
  * tempfile
  * smtplib
  * email.mime.multipart
  * emial.mime.text
  * qualysapi
  * pandas

====Script workflow====

  - **GET** Qualys reports list(**XML**) via Qualys API;
  - lookup for the all CSV(**OUTPUT_FORMAT**) report IDs, with Title(**TITLE**) started with '**JIRA_**'; 
  - loop for all these reports
    - compare this ID with recently processed ID's list, if there is no such ID -> process; else -> iterate next;
    - **GET** the Report ID via Qualys API(CSV);
    - truncate the Report header(**first 10 rows**);
    - parse this report for column names: **'['IP', 'DNS', 'OS', 'QID', 'Title', 'Vuln Status', 'Severity', 'Port', 'First Detected', 'Last Detected', 'CVE ID', 'CVSS Base', 'Threat', 'Impact', 'Solution', 'Results', 'PCI Vuln', 'Associated AGs']'**;
    - if '**CVSS Base**' is empty('**nan**') -> skip this row;
    - create parent Task using IP, DNS; 
    - duedate is set + timedelta(days=+90 from script running date), priority = Higest; .
    - encapsulate data of each rows in Jira query(**JSON**) using Jira **TASK** query template;
    - **POST** this data to Jira via API(**create new task**) ; parse Jira Task key from request;
    - then create Sub-Task using Task key as Parent; 
    - If CVSS_Base >= 8 duedate +90 from script running date) priority Higest; CVSS_Base >={6-60d-4-High/4-45d-Medium/2-30d-Low/1-15d-Lowest};
    - encapsulate data of each rows in Jira query(**JSON**) using Jira **SUB-TASK** query template;
    - **POST** this data to Jira via API(**create new sub-task**) ;
    - Reporter name both for Task and Subtask will be your Jira API user.
  - Send email report(log) as option, send user report(all processed/not processed reports and created Jira tickets) after iterating all found not processed reports.


====Qualys Creds File====

```
%
[info]
hostname = qualysapi.qualys.eu # Use your Qualys installation Region!
username = <your-user>
password = <your-pass>

# Set the maximum number of retries each connection should attempt. Note, this applies only to failed connections and timeouts, never to requests where
 the server returns a response.
max_retries = 10

[proxy]
; This section is optional. Leave it out if you're not using a proxy.
; You can use environmental variables as well: http://www.python-requests.org/en/latest/user/advanced/#proxies

; proxy_protocol set to https, if not specified.
proxy_url = http://your-proxy.dom

; proxy_port will override any port specified in proxy_url
proxy_port = 8080

; proxy authentication
#proxy_username = <your-user>
#proxy_password = <your-pass>
```

====Jira JSON TASK Template====

Check carefully these fields: **customfield_10200**, **customfield_11024**.

Most likely you don't have these fields in your Jira(but I do).

You'll have to change script body accordingly!

```
{
    "fields": {
        "project": {
            "key": "<YOUR PROJECT KEY>"
        },
        "issuetype": {
            "name": "Task"
        },
        "summary": "<QUALYS REPORT COLUMNS IP + DNS - MUST BE EMPTY>",
        "assignee": {
            "name": "<YOUR DEFAULT ASSIGNEE>"
        },
        "reporter": {
            "name": "<YOUR-JIRA-USER-FOR-API>"
        },
        "customfield_10200": "<START DATE CUSTOM FIELD(SCRIPT START DATE) - MUST BE EMPTY>",
        "duedate": "<COUNTED BY SCRIPT - MUST BE EMPTY>",
        "description": "<QUALYS REPORT COLUMN ASSOCIATED_AGS - MUST BE EMPTY>",
        "priority": {
            "name": "Highest"
        },
        "customfield_11024": [
            {
                "key": "<YOUR ETC STATIC CUSTOM FIELD - MY CASE = BUSINESS RELATED PROCESS>"
            }
        ]
    }
}
```

====Jira JSON SUB-TASK Template====

<WRAP center round important 100%>
Check carefully these fields: you must have custom fields for all Qualys report fields(json below).

You'll have to change script body accordingly!
</WRAP>

```
{
    "fields": {
        "project": {
            "key": "<YOUR PROJECT KEY>"
        },
		"parent": {
            "key": "<TASK KEY COUNTED BY SCRIPT - MUST BE EMPTY>"
        },
        "issuetype": {
            "name": "<YOUR SUBTASK NAME>"
        },
        "summary": "<QUALYS REPORT COLUMN TITLE - MUST BE EMPTY>",
        "assignee": {
            "name": "<YOUR DEFAULT ASSIGNEE>"
        },
        "reporter": {
            "name": "<YOUR-JIRA-USER-FOR-API>"
        },
	"customfield_11610": "<QUALYS REPORT COLUMN DNS - MUST BE EMPTY>",
	"customfield_11616": "<QUALYS REPORT COLUMN OS - MUST BE EMPTY>",
	"customfield_11612": "<QUALYS REPORT COLUMN QID - MUST BE EMPTY>",
	"customfield_11617": "<QUALYS REPORT COLUMN Vuln Status - MUST BE EMPTY>",
	"customfield_11615": "<QUALYS REPORT COLUMN Severity - MUST BE EMPTY>",
	"customfield_11618": "<QUALYS REPORT COLUMN Port - MUST BE EMPTY>",
	"customfield_11619": "<QUALYS REPORT COLUMN First Detected - MUST BE EMPTY>",
	"customfield_11620": "<QUALYS REPORT COLUMN Last Detected - MUST BE EMPTY>",
	"customfield_11621": "<QUALYS REPORT COLUMN CVE ID - MUST BE EMPTY>",
	"customfield_11622": "<QUALYS REPORT COLUMN CVSS Base - MUST BE EMPTY>",
	"customfield_11624": "<QUALYS REPORT COLUMN Impact - MUST BE EMPTY>",
	"customfield_11625": "<QUALYS REPORT COLUMN Solution - MUST BE EMPTY>",
	"customfield_11626": "<QUALYS REPORT COLUMN Results - MUST BE EMPTY>",
	"customfield_11627": "<QUALYS REPORT COLUMN PCI Vuln - MUST BE EMPTY>",
        "customfield_10200": "<START DATE CUSTOM FIELD(SCRIPT START DATE) - MUST BE EMPTY>",
        "duedate": "<COUNTED BY SCRIPT - MUST BE EMPTY>",
        "description": "<QUALYS REPORT COLUMN Threat - MUST BE EMPTY>",
        "priority": {
            "name": "<COUNTED BY SCRIPT - MUST BE EMPTY>"
        },
        "customfield_11024": [
            {
                "key": "<YOUR ETC STATIC CUSTOM FIELD - MY CASE = BUSINESS RELATED PROCESS>"
            }
        ]
    }
}
```
