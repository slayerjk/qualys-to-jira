import logging
from datetime import datetime, date
from os import mkdir, path
import json

# DEFINING WORK DIR(SCRIPT'S LOCATION)
'''
By default script uses script's location dir.
If you need custom path for script(sensitive) data
'''
work_dir = path.dirname(path.realpath(__file__))
data_files = f'{work_dir}/data_files'

# SCRIPT APPNAME(FOR SEND MAIL FUNCTION & ETC)
appname = 'qualys-to-jira'

# LOGGING SECTION

# DEFINE HOW MANY FILES TO KEEP(MOST RECENT)
logs_to_keep = 30
reports_to_keep = 30

today = datetime.now()
jira_date_format = date.today()

logs_dir = f'{work_dir}/logs'

if not path.isdir(logs_dir):
    mkdir(logs_dir)

app_log_name = f'{logs_dir}/{appname}_log_{str(today.strftime("%d-%m-%Y"))}.log'
logging.basicConfig(filename=app_log_name, filemode='w', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s', datefmt='%d-%b-%Y %H:%M:%S')

logging.info('#################################################')
logging.info('SCRIPT WORK STARTED: QUALYS REPORT TO JIRA TICKET')
logging.info('Script Starting Date&Time is: ' +
             str(today.strftime('%d/%m/%Y %H:%M:%S')) + '\n')


# DEFINING ALL NECESSARRY FOLDERS/FILES & API URLS VARIABLES
# LIST OF FOLDERS TO CREATE DIRS
list_of_folders = []

# DEFINING ALL NECESSARRY FOLDERS
qualys_files_dir = f'{work_dir}/qualys_files'
list_of_folders.append(qualys_files_dir)

qualys_reports = f'{qualys_files_dir}/reports'
list_of_folders.append(qualys_reports)

jira_files_dir = f'{work_dir}/jira_files'
list_of_folders.append(jira_files_dir)

# DEFINING FILES VARIABLES
qualys_reports_list = f'{qualys_files_dir}/qualys-reports-list.xml'
qualys_last_processed_reports = f'{qualys_files_dir}/qualys-last-processed-reports.txt'
qualys_report_ready = f'{qualys_files_dir}/qualys-report-ready.csv'

jira_query_task_template = f'{jira_files_dir}/QUAL_jira-query-task-template.json'
jira_query_subtask_template = f'{jira_files_dir}/QUAL_jira-query-subtask-template.json'
jira_query_file = f'{jira_files_dir}/jira-query.json'

# QUALYS API REPORTS LIST VARS
qualys_creds = f'{qualys_files_dir}/qualys-creds.txt'
qualys_api_url = '/api/2.0/fo/report/'
qualys_reports_for_jira = dict()

# JIRA API DATA
jira_data = f'{jira_files_dir}/jira-data.json'
try:
    with open(jira_data, 'r', encoding='utf-8') as file:
        data = json.load(file)
        jira_url = data['jira_url']
        jira_coded_creds = data['jira_coded_creds']
        jira_task_due_date = data['jira_task_due_date']
        cvss_8_and_more = data['cvss_8_and_more']
        cvss_6_and_more = data['cvss_6_and_more']
        cvss_4_and_more = data['cvss_4_and_more']
        cvss_2_and_more = data['cvss_2_and_more']
        cvss_1_and_more = data['cvss_1_and_more']
except Exception as e:
    raise Exception(f'NO JIRA DATA FOUND,/n{e}/n exiting')

jira_api_url = f'{jira_url}/rest/api/2/issue/'

jira_query_headers = {
    'Authorization': f'Basic {jira_coded_creds}',
    'X-Requested-With': 'qualys-to-jira-script',
    'Accept': 'application/json',
    'Content-Type': 'application/json'
}

jira_query_proxy = {
    'http': None,
    'https': None
}


# SMTP DATA(WITHOUT AUTH)
'''
Email report
'''
send_mail_option = 'yes'
mail_data = f'{work_dir}/data_files/mailing_data.json'
try:
    with open(mail_data, 'r', encoding='utf-8') as file:
        data = json.load(file)
        smtp_server = data['smtp_server']
        from_addr = data['smtp_from_addr']
        to_addr_list_users = data['list_users']
        to_addr_list_admins = data['list_admins']
        smtp_port = data['smtp_port']
except Exception as e:
    raise Exception(f'NO MAIL DATA FOUND,/n{e}/n exiting')
