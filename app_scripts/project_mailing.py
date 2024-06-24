import tempfile
from smtplib import SMTP
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from project_static import logging


# EMAIL REPORT FUNCTION
def send_mail_report(
        smtp_server: str,
        smtp_port: int,
        from_addr: str,
        appname: str,
        today: str,
        to_addr_list_admins: list,
        to_addr_list_users: list,
        user_report_temp: tempfile.TemporaryFile(),
        app_log_name: str,
        mail_type: str = None,
):
    """
    To send email report.
    By default, at the end of the script only.
    """
    message = MIMEMultipart()
    message["From"] = from_addr

    rcpt_to = None

    if mail_type == 'error':
        logging.info('START: sending email error report')
        message["Subject"] = f'{appname} - Script Error({today})'
        message["To"] = ', '.join(to_addr_list_admins)
        rcpt_to = to_addr_list_admins

    elif mail_type == 'report':
        logging.info('START: sending jira tasks final report')
        message["Subject"] = f'{appname} - Результат({today})'
        message["To"] = ', '.join(to_addr_list_users)
        rcpt_to = to_addr_list_users
        user_report_temp.seek(0)

    elif mail_type == 'log':
        logging.info('START: sending email final report')
        message["Subject"] = f'{appname} - Script Report({today})'
        message["To"] = ', '.join(to_addr_list_admins)
        rcpt_to = to_addr_list_admins

    input_file = None
    if mail_type == 'error' or mail_type == 'log':
        with open(app_log_name, 'r') as log:
            input_file = log.read()
    elif mail_type == 'report':
        input_file = user_report_temp.read()

    message.attach(MIMEText(input_file, "plain"))
    body = message.as_string()

    try:
        with SMTP(smtp_server, smtp_port) as send_mail:
            send_mail.ehlo()
            send_mail.sendmail(from_addr, rcpt_to, body)
            send_mail.quit()

            if mail_type == 'error' or mail_type == 'log':
                logging.info('DONE: sending email error report\n')
            elif mail_type == 'report':
                logging.info('DONE: user final report\n')
    except Exception as e:
        if mail_type == 'error':
            logging.exception(f'FAILED: sending email error report, moving on...\n{e}\n')
        else:
            logging.exception(f'FAILED: sending email final report, moving on...\n{e}\n')
