#!/usr/bin/env python3

'''
This script is automatization of creating Jira tickets,
based on Qualys scan report.
'''

import logging
from datetime import datetime, date, timedelta
from time import sleep
from os import mkdir, path, remove
from sys import exit
from pathlib import Path
import requests
from xml.etree.ElementTree import parse
from json import loads, dumps
import re
import tarfile
from smtplib import SMTP
from tempfile import TemporaryFile

### DEFINING WORK DIR(SCRIPT'S LOCATION) ###
work_dir = '<your-absolute-path>'

### SCRIPT APPNAME(FOR SEND MAIL FUNCTION & ETC)
appname = 'qualys-to-jira'

###########################
##### LOGGING SECTION #####
today = datetime.now()
jira_date_format = date.today()

logs_dir = work_dir+'/logs'

if not path.isdir(logs_dir):
    mkdir(logs_dir)

app_log_name = f'{logs_dir}/{appname}_log_{str(today.strftime("%d-%m-%Y"))}.log'
logging.basicConfig(filename=app_log_name, filemode='w', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s', datefmt='%d-%b-%Y %H:%M:%S')
logging.info('SCRIPT WORK STARTED: QUALYS REPORT TO JIRA TICKET')
logging.info('Script Starting Date&Time is: ' +
             str(today.strftime('%d/%m/%Y %H:%M:%S')) + '\n')

### ADDING EXTERNAL MODULES ###
try:
    from qualysapi import connect
except Exception as error:
    logging.exception('FAILURE: MODULE qualysapi MUST BE INSTALLED(pip3 install qualysapi)')
try:
    from pandas import read_csv, DataFrame
except Exception as error:
    logging.exception('FAILURE: MODULE pandas MUST BE INSTALLED(pip3 install pandas)')

######################################################################
##### DEFINING ALL NECESSARRY FOLDERS/FILES & API URLS VARIABLES #####

### LIST OF FOLDERS TO CREATE DIRS ###
list_of_folders = []

### DEFINING ALL NECESSARRY FOLDERS ###
qualys_files_dir = work_dir+'/qualys_files'
list_of_folders.append(qualys_files_dir)

qualys_reports = qualys_files_dir+'/reports'
list_of_folders.append(qualys_reports)

jira_files_dir = work_dir+'/jira_files'
list_of_folders.append((jira_files_dir))

### DEFINING FILES VARIABLES ###
qualys_reports_list = qualys_files_dir+'/qualys-reports-list.xml'
qualys_last_processed_reports = qualys_files_dir + \
    '/qualys-last-processed-reports.txt'
qualys_report_ready = qualys_files_dir+'/qualys-report-ready.csv'

jira_query_task_template = jira_files_dir+'/QUAL_jira-query-task-template.json'
jira_query_subtask_template = jira_files_dir+'/QUAL_jira-query-subtask-template.json'
jira_query_file = jira_files_dir+'/jira-query.json'

### QUALYS API REPORTS LIST VARS ###
qualys_creds = qualys_files_dir+'/qualys-creds.txt'
qualys_api_url = '/api/2.0/fo/report/'

### JIRA API DATA ###
jira_api_url = 'https://jira.bcc.kz/rest/api/2/issue/'
jira_coded_creds = '<YOUR_JIRA_BASE64_CREDS - ACCOUNT:PASSWORD>'

jira_query_headers = {
    'Authorization': 'Basic '+jira_coded_creds,
    'X-Requested-With': 'qualys-to-jira-script',
    'Accept': 'application/json',
    'Content-Type': 'application/json'
}

jira_tasks_count = 0
jira_subtasks_count = 0
jira_tasks_final_temp = TemporaryFile('w+t')

### SMTP DATA(WITHOUT AUTH) ###
'''
Email report
'''
send_mail_option = 'yes'
smtp_server = '<YOUR_SMTP_SERVER>'
from_addr = f'{appname}@EX.COM'
to_addr_list_users = ['USER@EX.COM']
to_addr_list_admins = ['ADMIN@EX.COM']
smtp_port = 25

#####################
##### FUNCTIONS #####

##### FILES ROTATION #####

### DEFINE HOW MANY FILES TO KEEP(MOST RECENT) ###
logs_to_keep = 30
reports_to_keep = 30

def files_rotate(path_to_rotate, num_of_files_to_keep):
    count_files_to_keep = 1
    basepath = sorted(Path(path_to_rotate).iterdir(), key=path.getctime, reverse=True)
    for entry in basepath:
        if count_files_to_keep > num_of_files_to_keep:
            remove(entry)
            logging.info('removed file is: '+str(entry))
        count_files_to_keep += 1

### ESTIMATED TIME ###

def count_script_job_time():
    end_date = datetime.now()
    logging.info('\nEstimated time is: ' + str(end_date - today) + '\n##########\n')

### EMAIL REPORT ###
'''
To send email report.
By default, at the end of the script only.
'''
def send_mail_report(type):
    if send_mail_option == 'yes':
        if type == 'error':
            logging.info('START: sending email error report')
            subj = f'{appname} - script error occured'
            rcpt_to = to_addr_list_admins
            with open(app_log_name, 'r') as log:
                body = log.read()
        elif type == 'tasks':
            logging.info('START: sending jira tasks final report')
            subj = f'{appname} - jira tasks final report'
            rcpt_to = to_addr_list_users
            body = jira_tasks_final_temp.read()
        elif type == 'report':
            logging.info('START: sending email final report')
            subj = f'{appname} - script final report'
            rcpt_to = to_addr_list_admins
            with open(app_log_name, 'r') as log:
                body = log.read()
        try:
            with SMTP(smtp_server, smtp_port) as send_mail:
                send_mail.ehlo()
                send_mail.sendmail(from_addr=from_addr, to_addrs=rcpt_to, msg=f'subject: {subj}({today})\n\n{today}:\n{body}')
                send_mail.quit()
                if type == 'error':
                    logging.info('DONE: sending email error report\n')
                elif type == 'tasks':
                    logging.info('DONE: jira tasks final report\n')
                else:
                    logging.info('DONE: sending email final report\n')
        except Exception as e:
            if type == 'error':
                logging.exception('FAILED: sending email error report, moving on...\n')
            else:
                logging.exception('FAILED: sending email final report, moving on...\n')

#############################
##### PRE-START ACTIONS #####

logging.info('STARTED: PRE-START ACTIONS')

### CHECKING JIRA TEMPLATES EXISTS ###
if not path.isfile(jira_query_task_template):
    logging.exception('FAILURE: Jira query Task template NOT FOUND, exiting...')
    send_mail_report('error')
    exit()

if not path.isfile(jira_query_subtask_template):
    logging.exception('FAILURE: Jira query Sub-Task template NOT FOUND, exiting...')
    send_mail_report('error')
    exit()

### CREATING ALL NECESSARRY FOLDERS ###
logging.info('Starting to create all necessarry folders...')
for folder in list_of_folders:
    try:
        if mkdir(folder):
            logging.info(folder+': created')
    except FileExistsError as error:
        logging.info(folder+': exists, skipping')

logging.info('DONE: PRE-START ACTIONS\n')

###########################################
##### MODULE: GET QUALYS REPORTS LIST #####

logging.info('STARTED: GET QUALYS REPORTS LIST')
try:
    qualys_request_get_reports_list = connect(qualys_creds)
except Exception as error:
    logging.exception('FAILURE: Failed to GET Qualys reports list, exiting...')
    send_mail_report('error')
    exit()

### QUALYS GET REPORT LIST API PARAMS ###
qualys_reports_list_params = {
    'action': 'list'
}
### PERFORM API REQUEST ###
resp = qualys_request_get_reports_list.request(
    qualys_api_url, qualys_reports_list_params)
try:
    with open(qualys_reports_list, 'w', encoding='utf_8_sig') as f:
        print(resp, file=f)
        f.close()
        logging.info('GET Qualys Report List - DONE!')
except Exception as error:
    logging.exception('FAILURE: Failed to GET Qualys reports list, exiting...')
    send_mail_report('error')
    exit()

logging.info('DONE: GET QUALYS REPORTS LIST\n')

##########################################################################################
##### MODULE: PARSE QUALYS REPORTS LIST, CHECK IF EXISTS IN PROCESSESD RERPORTS LIST #####

logging.info('STARTED: PARSE QUALYS REPORTS LIST, CHECK IF EXISTS IN PROCESSESD RERPORTS LIST')
mytree = parse(qualys_reports_list)
myroot = mytree.getroot()
reports_list = myroot[0][1]

try:
    for rep_data in reports_list.findall('REPORT'):
        rep_id = rep_data.find('ID').text
        rep_title = rep_data.find('TITLE').text
        rep_format = rep_data.find('OUTPUT_FORMAT').text
        # rep_launch_date = rep_data.find('LAUNCH_DATETIME').text

        if rep_title.startswith('JIRA_') and rep_format.startswith('CSV'):
            logging.info('FOUND CSV REPORT: ' + str(rep_id))
            break
except Exception as error:
    logging.exception('FAILURE: Failed Parsing Qualys Reports List, exiting...')
    send_mail_report('error')
    exit()

logging.info('Checking Last CSV Report id has been processed...')
try:
    if path.isfile(qualys_last_processed_reports):
        logging.info(
            'qualys_last_processed_reports exists, continue...')
    else:
        logging.exception(
            'qualys_last_processed_reports is not exist, creating...')
        f = open(qualys_last_processed_reports, 'w')
        f.close()
    with open(qualys_last_processed_reports, 'r') as rep_check_list:
        count = 0
        for line in rep_check_list.readlines():
            if line.startswith(rep_id):
                count += 1
                logging.info(
                    'FOUND DUBLICATE REPORT(skipping): ' + line)
                break
        if count == 0:
            rep_id_to_download = rep_id
            logging.info(
                str(rep_id) + ' not found in reports check list')
            logging.info('Continue with this report ID')
            rep_id_new = 'yes'
        else:
            rep_id_new = 'no'
except Exception as error:
    logging.exception(
        'FAILURE: Failed to check if Last CSV Report id has been processed, exiting...')
    send_mail_report('error')
    exit()

if rep_id_new == 'no':
    logging.warning('THERE IS NO NEW CSV REPORT TO PROCESS\n')
    logging.info('Starting log rotation...')
    try:
        files_rotate(logs_dir, logs_to_keep)
    except Exception as error:
        logging.exception('FAILURE: failed to rotate logs')
    logging.info('Finished log rotation\n')
    logging.info('SCRIPT WORK DONE: QUALYS REPORT TO JIRA TICKET')
    send_mail_report('report')
    exit()

logging.info('DONE: PARSE QUALYS REPORTS LIST, CHECK IF EXISTS IN PROCESSESD RERPORTS LIST\n')

#######################################################
### MODULE: GETTING NEW REPORT ID AND SAVING TO CSV ###

logging.info('STARTED: GETTING NEW REPORT ID AND SAVING TO CSV')

try:
    qualys_request_get_report = connect(qualys_creds)
except Exception as error:
    logging.exception('FAILURE: Failed to GET Qualys CSV Report, exiting...')
    send_mail_report('error')
    exit()

### QUALYS GET REPORT ID API PARAMS ###
qualys_get_report_params = {
    'action': 'list',
    'action': 'fetch',
    'id': rep_id_to_download
}
### DEFINING QUALYS CSV REPORT AND ITS ARCHIVE NAME ###
qualys_report_arcname = 'qualys-report_'+str(rep_id_to_download)+'.csv'
qualys_report = qualys_reports+'/'+qualys_report_arcname
qualys_reports_archive = qualys_reports+'/'+qualys_report_arcname+'.tar.gz'

### PERFORM API REQUEST ###
resp = qualys_request_get_report.request(
    qualys_api_url, qualys_get_report_params)

# print(resp) # Raw text response from Qualys
try:
    with open(qualys_report, 'w', encoding='utf-8') as f:
        print(resp, file=f)
except Exception as error:
    logging.exception(
        'FAILURE: Failed to GET/Save Qualys CSV Report Data, exiting')
    send_mail_report('error')
    exit()

logging.info('DONE: GETTING NEW REPORT ID AND SAVING TO CSV\n')

#######################################
##### MODULE: MODIFY CSV TO PARSE #####

### SEARCH ASSIGNEE FOR JIRA TEMPLATES
logging.info('STARTED: searching jira assignee from qualys report')
jira_assignee_pattern = 'Assignee_(\w+)_'

with open(qualys_report, 'r', encoding='utf-8') as report:
    try:
        jira_assignee = str(re.findall(jira_assignee_pattern, report.read())[0]).upper()
    except IndexError as e:
        logging.exception('FAILURE: searching jira assignee from qualys report, exiting')
        send_mail_report('error')
        exit()
logging.info('DONE: searching jira assignee from qualys report')
logging.info(f'Jira assignee is: {jira_assignee}\n')

### DEL SKIPROWS=10 WILL SKIP THE FIRST 10 LINES(HEADER) AND TRY TO READ FROM 11 LINE ###
logging.info('STARTED: trying delete first 10 rows of csv header...')
try:
    df = read_csv(qualys_report, index_col='IP', skiprows=10)
except Exception as error:
    logging.exception('FAILURE: trying delete first 10 rows of csv header, exiting...')
    send_mail_report('error')
    exit()
logging.info('STARTED: Writing downloaded CSV report modification')
try:
    df.to_csv(qualys_report_ready)
except Exception as error:
    logging.exception(
        'FAILURE: Writing downloaded CSV report modification, exiting...')
    send_mail_report('error')
    exit()

logging.info('DONE: MODIFY CSV TO PARSE\n')

####################################################################################
##### MODULE: PARSE CSV & ADD VALUES TO JIRA JSON TEMPLATE AND SEND IT TO JIRA #####

logging.info('STARTED: PARSE CSV & ADD VALUES TO JIRA JSON TEMPLATE AND SEND IT TO JIRA')

data = read_csv(qualys_report_ready)
df = DataFrame(data, columns=['IP', 'DNS', 'OS', 'QID', 'Title', 'Vuln Status', 'Severity', 'Port', 'First Detected',
                  'Last Detected', 'CVE ID', 'CVSS Base', 'Threat', 'Impact', 'Solution', 'Results', 'PCI Vuln', 'Associated AGs'])

### REGEXP PATTERN TO SEARCH CVSS BASE VALUE ###
cvss_base_pattern = '(\d+)\.'

### QUALYS IPS LIST TO CHECK TASK/SUB-TASK ###
jira_tasks_ips = []
### JIRA TASK KEYS LIST AND REGEXP PATTERN ###
jira_task_keys = []
jira_task_key_pattern = '^.*"key":"(.*)",.*$'
'''
b'{"id":"46475","key":"QUAL-2919","self":"https://jira.bcc.kz/rest/api/2/issue/46475"}' 
b'{"id":"46476","key":"QUAL-2920","self":"https://jira.bcc.kz/rest/api/2/issue/46476"}'
'''

for ind in df.index:
    if str(df['CVSS Base'][ind]) == 'nan':
        continue
    IP = str(df['IP'][ind])
    DNS = str(df['DNS'][ind])
    OS = str(df['OS'][ind])
    QID = str(df['QID'][ind])
    Title = str(df['Title'][ind])
    Vuln_Status = str(df['Vuln Status'][ind])
    Severity = str(df['Severity'][ind])
    Port = str(df['Port'][ind])
    First_Detected = str(df['First Detected'][ind])
    Last_Detected = str(df['Last Detected'][ind])
    CVE_ID = str(df['CVE ID'][ind])
    CVSS_Base = str(df['CVSS Base'][ind])
    Threat = str(df['Threat'][ind])
    Impact = str(df['Impact'][ind])
    Solution = str(df['Solution'][ind])
    Results = str(df['Results'][ind])
    PCI_Vuln = str(df['PCI Vuln'][ind])
    Associated_AGs = str(df['Associated AGs'][ind])
    
    ### CHECKING: CREATE TASK ###
    if IP not in jira_tasks_ips:
        jira_tasks_ips.append(IP)
        logging.info('Starting to encapsulate CSV report data to JIRA TASK query...')
        try:
            with open(jira_query_task_template, 'r', encoding='utf_8_sig') as reader, open(jira_query_file, 'w', encoding='utf_8_sig') as writer:
                temp_data = loads(reader.read())
                temp_data['fields']['summary'] = IP + ' - ' + DNS
                temp_data['fields']['assignee']['name'] = jira_assignee
                ### 'CUSTOMFIELD_10200' STANDS FOR START DATE ###
                temp_data['fields']['customfield_10200'] = str(jira_date_format)
                temp_data['fields']['description'] = Associated_AGs
                temp_data['fields']['duedate'] = str(
                        jira_date_format + timedelta(days=+90))
                temp_data['fields']['priority']['name'] = 'Highest'
                insert_data = dumps(temp_data, indent=4)
                writer.write(insert_data)
                writer.close()
                ### SEND JSON QUERY(TASK) TO JIRA API ###
                logging.info('Sending JSON data(TASK) to Jira API...')
                try:
                    jira_api_request = requests.post(jira_api_url, data=open(jira_query_file, 'rb'), headers=jira_query_headers)
                except Exception as error:
                    logging.exception('FAILURE: failed to send JSON data(TASK) to Jira API, exiting...')
                    send_mail_report('error')
                    exit()
                if jira_api_request.status_code == 201:
                    logging.info('Sending JSON data(TASK) to Jira API - DONE!')
                    jira_tasks_count += 1
                    logging.info(jira_api_request.text)
                    jira_task_keys.append(f'TASK: {re.findall(jira_task_key_pattern, jira_api_request.text)[0]}')
                    logging.info('Sleeping for 1 seconds before next POST...')
                    ### DEFINING PARENT TASK NAME ###
                    task_parent_key = re.findall('.*,"key":"(.*)",.*$', jira_api_request.text)[0]
                    sleep(1)
                else:
                    logging.warning('Something wrong, check this status code: ' + str(jira_api_request.status_code))
                    #logging.warning(jira_api_request.text)
                    send_mail_report('error')
                    exit()
        except Exception as error:
            logging.exception(
                'FAILURE: Failed to encapsulate modified CSV report data to JIRA query, exiting...')
            send_mail_report('error')
            exit()
    ### CHECKING: CREATE SUBTASK ###
    logging.info('Starting to encapsulate CSV report data to JIRA SUB-TASK query...')
    try:
        with open(jira_query_subtask_template, 'r', encoding='utf_8_sig') as reader, open(jira_query_file, 'w', encoding='utf_8_sig') as writer:
            temp_data = loads(reader.read())
            temp_data['fields']['parent']['key'] = task_parent_key
            temp_data['fields']['summary'] = Title
            temp_data['fields']['assignee']['name'] = jira_assignee
            temp_data['fields']['description'] = Threat
            temp_data['fields']['customfield_11616'] = OS
            temp_data['fields']['customfield_11612'] = QID
            temp_data['fields']['customfield_11617'] = Vuln_Status
            temp_data['fields']['customfield_11615'] = Severity
            temp_data['fields']['customfield_11618'] = Port
            temp_data['fields']['customfield_11619'] = First_Detected
            temp_data['fields']['customfield_11620'] = Last_Detected
            temp_data['fields']['customfield_11621'] = CVE_ID
            temp_data['fields']['customfield_11622'] = CVSS_Base
            temp_data['fields']['customfield_11624'] = Impact
            temp_data['fields']['customfield_11625'] = Solution
            temp_data['fields']['customfield_11626'] = Results
            temp_data['fields']['customfield_11627'] = PCI_Vuln
            ### 'CUSTOMFIELD_10200' STANDS FOR START DATE ###
            temp_data['fields']['customfield_10200'] = str(jira_date_format)
            temp_data['fields']['description'] = Threat
            ### CALCULATING PRIORITY AND DUEDATE ###
            if int(re.findall(cvss_base_pattern, CVSS_Base)[0]) >= 8:
                temp_data['fields']['priority']['name'] = 'Highest'
                temp_data['fields']['duedate'] = str(
                    jira_date_format + timedelta(days=+15))
            elif int(re.findall(cvss_base_pattern, CVSS_Base)[0]) >= 6:
                temp_data['fields']['priority']['name'] = 'High'
                temp_data['fields']['duedate'] = str(
                    jira_date_format + timedelta(days=+30))
            elif int(re.findall(cvss_base_pattern, CVSS_Base)[0]) >= 4:
                temp_data['fields']['priority']['name'] = 'Medium'
                temp_data['fields']['duedate'] = str(
                    jira_date_format + timedelta(days=+45))
            elif int(re.findall(cvss_base_pattern, CVSS_Base)[0]) >= 2:
                temp_data['fields']['priority']['name'] = 'Low'
                temp_data['fields']['duedate'] = str(
                    jira_date_format + timedelta(days=+60))
            elif int(re.findall(cvss_base_pattern, CVSS_Base)[0]) >= 1:
                temp_data['fields']['priority']['name'] = 'Lowest'
                temp_data['fields']['duedate'] = str(
                    jira_date_format + timedelta(days=+90))
            insert_data = dumps(temp_data, indent=4)
            writer.write(insert_data)
            writer.close()
            ### SEND JSON QUERY(SUB-TASK) TO JIRA API ###
            logging.info('Sending JSON data(SUB-TASK) to Jira API...')
            try:
                jira_api_request = requests.post(jira_api_url, data=open(jira_query_file, 'rb'), headers=jira_query_headers)
            except Exception as error:
                logging.exception('FAILURE: failed to send JSON data(SUB-TASK) to Jira API, exiting...')
                send_mail_report('error')
                exit()
            if jira_api_request.status_code == 201:
                logging.info('Sending JSON data(SUB-TASK) to Jira API - DONE!')
                jira_subtasks_count += 1
                logging.info(str(jira_api_request.text))
                jira_task_keys.append(f'SUB-TASK: {re.findall(jira_task_key_pattern, jira_api_request.text)[0]}')
                logging.info('Sleeping for 1 seconds before next request...')
                sleep(1)
            else:
                logging.warning('Something wrong, check this status code: ' + str(jira_api_request.status_code))
                #logging.warning(jira_api_request.text)
                send_mail_report('error')
                exit()
    except Exception as error:
        logging.exception(
            'FAILURE: Failed to encapsulate modified CSV report data to JIRA query, exiting...')
        send_mail_report('error')
        exit()

logging.info('DONE: PARSE CSV & ADD VALUES TO JIRA JSON TEMPLATE AND SEND IT TO JIRA\n')

#####################
##### POST JOBS #####

logging.info('STARTED: POST JOBS')

logging.info('Writing processed report ID to processed reports check list...')

try:
    with open(qualys_last_processed_reports, 'a+') as rep_check_list:
        rep_check_list.writelines(rep_id_to_download+'\n')
except Exception as error:
    logging.exception(
        'FAILURE: failed to Write Last CSV Report ID to processed reports list, exiting...')
    send_mail_report('error')
    exit()

logging.info('Archiving(tar.gz) downloaded qualys report..')
try:
    with tarfile.open(qualys_reports_archive, mode='w:gz') as tar:
        tar.add(qualys_report, arcname=qualys_report_arcname)
except Exception as error:
    logging.exception(
        'Failed to archive qualys report...')

logging.info('Removing all temporary files:')
try:
    logging.info('Removing temporary qualys_report_ready...')
    remove(qualys_report_ready)
    logging.info('Removing  unarchived qualys report...')
    remove(qualys_report)
    if jira_tasks_count != 0:
        logging.info('Removing temporary Jira query...')
        remove(jira_query_file)
    #logging.info('Removing temporary Qualys reports list...')
    #remove(qualys_reports_list)
except Exception as error:
    logging.exception(
        'Failed all/some temporary files...\n')

logging.info('STARTING FILES ROTATION...')
logging.info('Starting log rotation...')
try:
    files_rotate(logs_dir, logs_to_keep)
except Exception as error:
    logging.exception('FAILURE: failed to rotate logs')
logging.info('Finished log rotation\n')    
logging.info('Starting reports rotation...')
try:
    files_rotate(qualys_reports, reports_to_keep)
except Exception as error:
    logging.exception('FAILURE: failed to rotate reports')
logging.info('Finished reports rotation')    
logging.info('Finished Files Rotation\n')

logging.info('DONE: POST JOBS\n')

logging.info('SCRIPT WORK DONE: QUALYS REPORT TO JIRA TICKET')
if jira_tasks_count == 0:
    logging.warning('NO JIRA TASKS CREATED: Qualys report might be empty!')
else:
    logging.info('Jira TASKS created: ' + str(jira_tasks_count))
    logging.info('Jira SUB-TASKS created: ' + str(jira_subtasks_count))
    logging.info('LIST of Jira task/sub-task keys created:\n-----')
    ### PRINT ALL CREATED JIRA TASKS
    for task in jira_task_keys:
        logging.info(task)
        jira_tasks_final_temp.write(str(task)+'\n')
    jira_tasks_final_temp.seek(0)
    send_mail_report('tasks')

count_script_job_time()
send_mail_report('report')
