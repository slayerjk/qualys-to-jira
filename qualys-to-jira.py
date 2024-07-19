#!/usr/bin/env python3

"""
This script is automatization of creating Jira tickets,
based on Qualys scan report.

Python modules to install first:
  * qualysapi
  * pandas
"""

import logging
from datetime import timedelta
from time import sleep
from os import mkdir, path, remove
from sys import exit
from platform import system as platform_system

import requests
import urllib3
from xml.etree.ElementTree import parse
from json import loads, dumps
import re
import tarfile
from tempfile import TemporaryFile
from qualysapi import connect
from pandas import read_csv, DataFrame

from project_static import (
    logs_to_keep,
    reports_to_keep,
    jira_query_subtask_template,
    jira_query_task_template,
    today,
    list_of_folders,
    qualys_creds,
    qualys_api_url,
    qualys_reports,
    qualys_reports_list,
    qualys_last_processed_reports,
    qualys_reports_for_jira,
    logs_dir,
    qualys_report_ready,
    jira_query_file,
    jira_date_format,
    jira_api_url,
    jira_query_headers,
    jira_query_proxy,
    smtp_port,
    smtp_server,
    from_addr,
    appname,
    to_addr_list_users,
    to_addr_list_admins,
    app_log_name
)

from app_scripts.project_helper import files_rotate, count_script_job_time

from app_scripts.project_mailing import send_mail_report

# Disable urllib warnings
urllib3.disable_warnings()

# CREATING USER REPORT FILE
user_report_temp = TemporaryFile('w+t')
user_report_temp.write(f'SCRIPT WORK STARTED QUALYS - {today}\n\n')

# MAIL SETTINGS
mail_settings = [
    smtp_server,
    smtp_port,
    from_addr,
    appname,
    today,
    to_addr_list_admins,
    to_addr_list_users,
    user_report_temp,
    app_log_name
]

# PRE-START ACTIONS
logging.info('STARTED: PRE-START ACTIONS')

# CHECKING JIRA TEMPLATES EXISTS
if not path.isfile(jira_query_task_template):
    logging.exception('FAILED: Jira query Task template NOT FOUND, exiting...')
    send_mail_report(*mail_settings, mail_type='error')
    exit()

if not path.isfile(jira_query_subtask_template):
    logging.exception('FAILED: Jira query Sub-Task template NOT FOUND, exiting...')
    send_mail_report(*mail_settings, mail_type='error')
    exit()

# CREATING ALL NECESSARRY FOLDERS
logging.info('Starting to create all necessarry folders...')
for folder in list_of_folders:
    try:
        if mkdir(folder):
            logging.info(folder+': created')
    except FileExistsError as error:
        logging.info(folder+': exists, skipping')

logging.info('DONE: PRE-START ACTIONS\n')

# MODULE: GET QUALYS REPORTS LIST
logging.info('STARTED: GET QUALYS REPORTS LIST')
try:
    qualys_request_get_reports_list = connect(qualys_creds)
except Exception as e:
    logging.exception(f'FAILED: Failed to GET Qualys reports list,\n{e}\n exiting...')
    send_mail_report(*mail_settings, mail_type='error')
    exit()
else:
    logging.info('DONE: GET QUALYS REPORTS LIST\n')


# QUALYS GET REPORT LIST API PARAMS
qualys_reports_list_params = {
    'action': 'list'
}

# PERFORM API REQUEST
logging.info('STARTED: getting qualys reports list parameters')
try:
    resp = qualys_request_get_reports_list.request(
        qualys_api_url, qualys_reports_list_params, verify=False)
except Exception as e:
    logging.exception(f'FAILED: getting qualys reports list parameters,\n{e}\nexiting')
    send_mail_report(*mail_settings, mail_type='error')
    exit()
else:
    logging.info('DONE: getting qualys reports list parameters\n')

logging.info('STARTED: writing qualys api response to report list')
try:
    with open(qualys_reports_list, 'w', encoding='utf_8_sig') as f:
        print(resp, file=f)
        f.close()
except Exception as error:
    logging.exception(f'FAILED: writing qualys api response to report list,\n{error}\n exiting...')
    send_mail_report(*mail_settings, mail_type='error')
    exit()
else:
    logging.info('DONE: writing qualys api response to report list\n')


# MODULE: PARSE QUALYS REPORTS LIST, CHECK IF EXISTS IN PROCESSESD RERPORTS LIST
logging.info('STARTED: Checking qualys_last_processed_reports exists...')
try:
    if path.isfile(qualys_last_processed_reports):
        logging.info(
            'qualys_last_processed_reports exists, continue...')
    else:
        logging.warning(
            'qualys_last_processed_reports is not exist, creating...')
        f = open(qualys_last_processed_reports, 'w')
        f.close()
except Exception as error:
    logging.exception(f'FAILED: Checking qualys_last_processed_reports exists,\n{error}\nexiting...')
    send_mail_report(*mail_settings, mail_type='error')
    exit()
logging.info('DONE: Checking qualys_last_processed_reports exists\n')

logging.info(f'STARTED: PARSE QUALYS REPORTS LIST & CHECK IF EXISTS IN PROCESSESD RERPORTS LIST\n')
mytree = parse(qualys_reports_list)
myroot = mytree.getroot()
reports_list = myroot[0][1]

try:
    logging.info('START: forming last processed report list')
    with open(qualys_last_processed_reports, 'r') as rep_check_list:
        try:
            list_qualys_last_processed_reports = [int(i.strip()) for i in rep_check_list.readlines()]
        except ValueError as e:
            logging.exception('FAILED: forming last processed report list, not number in list, exiting...')
            send_mail_report(*mail_settings, mail_type='error')
            exit()
    logging.info('DONE: forming Qualys last processed report list')
    logging.info(f'Last processed reports is:\n{list_qualys_last_processed_reports}\n')        

    for rep_data in reports_list.findall('REPORT'):
        rep_id = rep_data.find('ID').text
        rep_title = rep_data.find('TITLE').text
        rep_format = rep_data.find('OUTPUT_FORMAT').text
        # rep_launch_date = rep_data.find('LAUNCH_DATETIME').text
        
        if rep_title.startswith('JIRA_') and rep_format.startswith('CSV'):
            logging.info(f'FOUND CSV REPORT FOR JIRA: {rep_id}:{rep_title}')
            user_report_temp.write(f'PROPER QUALYS REPORT FOUND: {rep_id}:{rep_title}\n')
            
            logging.info(f'Checking Report id({rep_id}) has been processed')
            is_processed = False
            for val in list_qualys_last_processed_reports:
                if int(rep_id) <= int(val):
                    logging.info(f'{rep_id} HAS BEEN PROCESSED ALREADY, skipping this report\n')
                    user_report_temp.write(f'{rep_id}:{rep_title} - HAS BEEN PROCESSED ALREADY\n\n')
                    is_processed = True
                    break
            if not is_processed:
                logging.info(f'NEW REPORT FOR JIRA HAS FOUND: {rep_id}:{rep_title}\n')
                user_report_temp.write(f'{rep_id}:{rep_title} - NEW REPORT TO PROCESS\n\n')
                qualys_reports_for_jira[rep_id] = rep_title
except Exception as error:
    logging.exception(f'FAILED: Parsing Qualys Reports List,\n{error}\nexiting...')
    send_mail_report(*mail_settings, mail_type='error')
    exit()
logging.info(f'DONE: PARSE QUALYS REPORTS LIST & CHECK IF EXISTS IN PROCESSESD RERPORTS LIST\n')

if len(qualys_reports_for_jira) == 0:
    logging.warning('THERE IS NO NEW CSV REPORT TO PROCESS\n')
    user_report_temp.write('NO PROPER REPORTS TO PROCESS, EXITING')
    send_mail_report(*mail_settings, mail_type='report')
    logging.info('Starting log rotation...')
    try:
        files_rotate(logs_dir, logs_to_keep)
    except Exception as error:
        logging.exception(f'FAILED: failed to rotate logs\n{error}\n')
    logging.info('Finished log rotation\n')
    logging.info('SCRIPT WORK DONE: QUALYS REPORT TO JIRA TICKET')
    send_mail_report(*mail_settings, mail_type='log')
    exit()
else:
    logging.info('STARTED: showing final report list to prcess:')
    qualys_reports_for_jira = dict(sorted(qualys_reports_for_jira.items(), key=lambda x: x[0]))
    for key, value in qualys_reports_for_jira.items():
        logging.info(f'{key}: {value}')
    logging.info('DONE: showing final report list to prcess\n')


# MODULE: GETTING NEW REPORT ID AND SAVING TO CSV
logging.info('STARTED: TO ITERATE OVER QUALYS REPORTS LIST FOR JIRA\n')
for cur_rep_id, cur_rep_title in qualys_reports_for_jira.items():

    jira_tasks_count = 0
    jira_subtasks_count = 0

    logging.info('------------------------------------------------')
    logging.info('STARTED: GETTING NEW REPORT ID AND SAVING TO CSV')
    try:
        qualys_request_get_report = connect(qualys_creds)
    except Exception as error:
        logging.exception(f'FAILED: Failed to GET Qualys CSV Report,\n{error}\nexiting...')
        send_mail_report(*mail_settings, mail_type='error')
        exit()

    # QUALYS GET REPORT ID API PARAMS
    qualys_get_report_params = {
        'action': 'fetch',
        'id': cur_rep_id
    }

    # DEFINING QUALYS CSV REPORT AND ITS ARCHIVE NAME
    qualys_report_arcname = 'qualys-report_'+str(cur_rep_id)+'.csv'
    qualys_report = qualys_reports+'/'+qualys_report_arcname
    qualys_reports_archive = qualys_reports+'/'+qualys_report_arcname+'.tar.gz'

    # PERFORM API REQUEST
    resp = qualys_request_get_report.request(
        qualys_api_url, qualys_get_report_params)
    # print(resp) # Raw text response from Qualys

    try:
        with open(qualys_report, 'w', encoding='utf-8') as f:
            print(resp, file=f)
    except Exception as error:
        logging.exception(f'FAILED: Failed to GET/Save Qualys CSV Report Data,\n{error}\nexiting')
        send_mail_report(*mail_settings, mail_type='error')
        exit()
    logging.info('DONE: GETTING NEW REPORT ID AND SAVING TO CSV\n')

    # MODULE: MODIFY CSV TO PARSE

    # SEARCH ASSIGNEE FOR JIRA TEMPLATES
    logging.info(f'STARTED: searching jira assignee for report({cur_rep_id}:{cur_rep_title})')
    jira_assignee_pattern = r'Assignee_(\w+)_'

    with open(qualys_report, 'r', encoding='utf-8') as report:
        try:
            jira_assignee = str(re.findall(jira_assignee_pattern, report.read())[0]).upper()
        except IndexError as e:
            logging.exception('FAILED: searching jira assignee from qualys report, exiting')
            send_mail_report(*mail_settings, mail_type='error')
            exit()
    logging.info('DONE: searching jira assignee from qualys report')
    logging.info(f'Jira assignee is: {jira_assignee}\n')

    if platform_system() != 'Windows':
        logging.info('STARTED: trying delete first 10 rows of csv header...')
        try:
            df = read_csv(qualys_report, index_col='IP', skiprows=10)
        except Exception as error:
            logging.exception(f'FAILED: trying delete first 10 rows of csv header,\n{error}\nexiting...')
            send_mail_report(*mail_settings, mail_type='error')
            exit()
        logging.info('DONE: trying delete first 10 rows of csv header...\n')

    logging.info('STARTED: writing downloaded CSV report modification')
    try:
        df.to_csv(qualys_report_ready)
    except Exception as error:
        logging.exception(f'FAILED: Writing downloaded CSV report modification,\n{error}\nexiting...')
        send_mail_report(*mail_settings, mail_type='error')
        exit()
    logging.info('DONE: writing downloaded CSV report modification\n')

    # MODULE: PARSE CSV & ADD VALUES TO JIRA JSON TEMPLATE AND SEND IT TO JIRA
    logging.info('STARTED: PARSE CSV & ADD VALUES TO JIRA JSON TEMPLATE AND SEND IT TO JIRA\n')

    data = read_csv(qualys_report_ready)
    df = DataFrame(data, columns=[
            'IP',
            'DNS',
            'OS',
            'QID',
            'Title',
            'Vuln Status',
            'Severity',
            'Port',
            'First Detected',
            'Last Detected',
            'CVE ID',
            'CVSS3.1 Base',
            'Threat',
            'Impact',
            'Solution',
            'Results',
            'PCI Vuln',
            'Associated AGs'
        ]
    )

    # REGEXP PATTERN TO SEARCH CVSS BASE VALUE
    cvss_base_pattern = r'(\d+)\.'

    # QUALYS IPS LIST TO CHECK TASK/SUB-TASK
    jira_tasks_ips = []

    # JIRA TASK KEYS LIST AND REGEXP PATTERN
    jira_task_keys = []
    jira_task_key_pattern = '^.*"key":"(.*)",.*$'
    '''
    b'{"id":"46475","key":"QUAL-2919","self":"https://<EXAMPLE.COM>/rest/api/2/issue/46475"}' 
    b'{"id":"46476","key":"QUAL-2920","self":"https://<EXAMPLE.COM>/rest/api/2/issue/46476"}'
    '''
    logging.info('STARTED: getting values from csv report')
    for ind in df.index:
        if str(df['CVSS3.1 Base'][ind]) == 'nan':
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
        CVSS_Base = str(df['CVSS3.1 Base'][ind])
        Threat = str(df['Threat'][ind])
        Impact = str(df['Impact'][ind])
        Solution = str(df['Solution'][ind])
        Results = str(df['Results'][ind])
        PCI_Vuln = str(df['PCI Vuln'][ind])
        Associated_AGs = str(df['Associated AGs'][ind])
        logging.info('DONE: getting values from csv report')

        # CHECKING: CREATE TASK
        if IP not in jira_tasks_ips:
            jira_tasks_ips.append(IP)
            logging.info('STARTED: encapsulating CSV report data to JIRA query...')
            try:
                with (open(jira_query_task_template, 'r', encoding='utf_8_sig') as reader,
                      open(jira_query_file, 'w', encoding='utf_8_sig') as writer):
                    temp_data = loads(reader.read())
                    temp_data['fields']['summary'] = IP + ' - ' + DNS
                    temp_data['fields']['assignee']['name'] = jira_assignee
                    # 'CUSTOMFIELD_10200' STANDS FOR START DATE
                    temp_data['fields']['customfield_10200'] = str(jira_date_format)
                    temp_data['fields']['description'] = Associated_AGs
                    temp_data['fields']['duedate'] = str(
                            jira_date_format + timedelta(days=+90))
                    temp_data['fields']['priority']['name'] = 'Highest'
                    insert_data = dumps(temp_data, indent=4)
                    writer.write(insert_data)
                    writer.close()

                    logging.info('DONE: encapsulating CSV report data to JIRA query...\n')

                    # SEND JSON QUERY(TASK) TO JIRA API
                    logging.info('START: Sending JSON data(TASK) to Jira API...')
                    try:
                        jira_api_request = requests.post(
                            jira_api_url,
                            data=open(jira_query_file, 'rb'),
                            headers=jira_query_headers,
                            proxies=jira_query_proxy
                        )
                    except Exception as error:
                        logging.exception(f'FAILED: Sending JSON data(TASK) to Jira API,\n{error}\nexiting...')
                        send_mail_report(*mail_settings, mail_type='error')
                        exit()
                    if jira_api_request.status_code == 201:
                        logging.info('DONE: Sending JSON data(TASK) to Jira API')
                        jira_tasks_count += 1
                        logging.info(jira_api_request.text)
                        jira_task_keys.append(f'TASK: {re.findall(jira_task_key_pattern, jira_api_request.text)[0]}')
                        logging.info('Sleeping for 1 seconds before next POST...\n')

                        # DEFINING PARENT TASK NAME
                        task_parent_key = re.findall('.*,"key":"(.*)",.*$', jira_api_request.text)[0]
                        sleep(1)
                    else:
                        logging.warning(
                            f'WARNING: Something wrong, check this status code: {str(jira_api_request.status_code)}, '
                            f'exiting')
                        logging.warning(jira_api_request.text)
                        send_mail_report(*mail_settings, mail_type='error')
                        exit()
            except Exception as error:
                logging.exception(f'FAILED: encapsulating CSV report data to JIRA query,\n{error}\nexiting...')
                send_mail_report(*mail_settings, mail_type='error')
                exit()

        # CHECKING: CREATE SUBTASK
        logging.info('STARTED: encapsulating CSV report data to JIRA SUB-TASK query...')
        try:
            with (open(jira_query_subtask_template, 'r', encoding='utf_8_sig') as reader,
                  open(jira_query_file, 'w', encoding='utf_8_sig') as writer):
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
                # 'CUSTOMFIELD_10200' STANDS FOR START DATE
                temp_data['fields']['customfield_10200'] = str(jira_date_format)
                temp_data['fields']['description'] = Threat
                # CALCULATING PRIORITY AND DUEDATE
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
                # SEND JSON QUERY(SUB-TASK) TO JIRA API
                logging.info('Sending JSON data(SUB-TASK) to Jira API...')
                try:
                    jira_api_request = requests.post(
                        jira_api_url,
                        data=open(jira_query_file, 'rb'),
                        headers=jira_query_headers,
                        proxies=jira_query_proxy
                    )
                except Exception as error:
                    logging.exception(f'FAILED: failed to send JSON data(SUB-TASK) to Jira API,\n{error}\nexiting...')
                    send_mail_report(*mail_settings, mail_type='error')
                    exit()
                if jira_api_request.status_code == 201:
                    logging.info('Sending JSON data(SUB-TASK) to Jira API - DONE!')
                    jira_subtasks_count += 1
                    logging.info(str(jira_api_request.text))
                    jira_task_keys.append(f'SUB-TASK: {re.findall(jira_task_key_pattern, jira_api_request.text)[0]}')
                    logging.info('Sleeping for 1 seconds before next request...\n')
                    sleep(1)
                else:
                    logging.warning('Something wrong, check this status code: ' + str(jira_api_request.status_code))
                    logging.warning(jira_api_request.text)
                    send_mail_report(*mail_settings, mail_type='error')
                    exit()
        except Exception as error:
            logging.exception(f'FAILED: Failed to encapsulate modified CSV report data to JIRA query,'
                              f'\n{error}\nexiting...')
            send_mail_report(*mail_settings, mail_type='error')
            exit()
    logging.info('DONE: PARSE CSV & ADD VALUES TO JIRA JSON TEMPLATE AND SEND IT TO JIRA\n')

    logging.info(f'STARTED: show result for {cur_rep_id}{cur_rep_title}')
    
    user_report_temp.write(f'RESULT FOR {cur_rep_id}:{cur_rep_title}\n')    
    
    if jira_tasks_count == 0:
        logging.warning('NO JIRA TASKS CREATED: Qualys report might be EMPTY!')
        user_report_temp.write('NO JIRA TASKES WAS CREATED, EMPTY QUALYS REPORT!\n\n')
    else:
        logging.info('Jira TASKS created: ' + str(jira_tasks_count))
        logging.info('Jira SUB-TASKS created: ' + str(jira_subtasks_count))
        logging.info('LIST of Jira task/sub-task keys created:\n-----')
        
        # PRINT ALL CREATED JIRA TASKS OPTIONALLY SEND USER REPORT
        user_report_temp.write(f'LIST OF JIRA TASKS CREATED:\n')
        for task in jira_task_keys:
            logging.info(task)
            user_report_temp.write(str(task)+'\n')
        logging.info('-----')
        user_report_temp.write('\n\n')
    logging.info('DONE: show created Jira tasks info')

    logging.info('STARTED: Archiving(tar.gz) downloaded qualys report..')
    try:
        with tarfile.open(qualys_reports_archive, mode='w:gz') as tar:
            tar.add(qualys_report, arcname=qualys_report_arcname)
    except Exception as error:
        logging.exception(f'Failed to archive qualys report,\n{error}\n...')
        send_mail_report(*mail_settings, mail_type='error')
    logging.info('DONE: Archiving(tar.gz) downloaded qualys report\n')

    logging.info('STARTED: Removing all temporary files:')
    try:
        logging.info('Removing temporary qualys_report_ready...')
        remove(qualys_report_ready)
        logging.info('Removing  unarchived qualys report...')
        remove(qualys_report)
        if jira_tasks_count != 0:
            logging.info('Removing temporary Jira query...')
            remove(jira_query_file)
        # logging.info('Removing temporary Qualys reports list...')
        # remove(qualys_reports_list)
    except Exception as error:
        logging.exception(f'Failed all/some temporary files,\n{error}\n...\n')
    logging.info('DONE: Removing all temporary files\n')
    logging.info('------------------------------------\n')

logging.info('DONE: TO ITERATE OVER QUALYS REPORTS LIST FOR JIRA\n')
    
# SEND FINAL REPORT FOR USERS
send_mail_report(*mail_settings, mail_type='report')

logging.info('STARTED: writing processed report ID to processed reports check list...')
try:
    with open(qualys_last_processed_reports, 'w') as rep_check_list:
        rep_check_list.write('\n'.join(qualys_reports_for_jira.keys()))
except Exception as error:
    logging.exception(
        f'FAILED: failed to Write Last CSV Report ID to processed reports list,\n{error}\nexiting...')
    send_mail_report(*mail_settings, mail_type='error')
    exit()
logging.info('DONE: writing processed report ID to processed reports check list\n')


# POST JOBS
logging.info('STARTED: POST JOBS\n')

logging.info('STARTED: log rotation...')
try:
    files_rotate(logs_dir, logs_to_keep)
except Exception as error:
    logging.exception(f'FAILED: failed to rotate logs\n{error}\n')
logging.info('DONE: log rotation\n')    

logging.info('STARTED: reports rotation...')
try:
    files_rotate(qualys_reports, reports_to_keep)
except Exception as error:
    logging.exception(f'FAILED: failed to rotate reports\n{error}\n')
logging.info('DONE: reports rotation\n')    

logging.info('DONE: POST JOBS\n')

logging.info('SCRIPT WORK DONE: QUALYS REPORT TO JIRA TICKET')
logging.info('##############################################')

count_script_job_time(today)
send_mail_report(*mail_settings, mail_type='log')
