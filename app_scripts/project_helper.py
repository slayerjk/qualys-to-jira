from pathlib import Path
from os import path, remove
from project_static import logging
from datetime import datetime


# FILES ROTATION FUNCTION
def files_rotate(path_to_rotate, num_of_files_to_keep):
    count_files_to_keep = 1
    basepath = sorted(Path(path_to_rotate).iterdir(), key=path.getctime, reverse=True)
    for entry in basepath:
        if count_files_to_keep > num_of_files_to_keep:
            remove(entry)
            logging.info('removed file is: '+str(entry))
        count_files_to_keep += 1


# ESTIMATED TIME
def count_script_job_time(today):
    end_date = datetime.now()
    logging.info('\nEstimated time is: ' + str(end_date - today) + '\n##########\n')
