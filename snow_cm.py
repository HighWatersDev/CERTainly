import requests
import json
import os
from datetime import datetime, timedelta
import logging
from os.path import join, dirname
from dotenv import load_dotenv

dotenv_path = join(dirname(__file__), '.env')
load_dotenv(dotenv_path)
snow_user = os.getenv("snow_username")
snow_password = os.getenv("snow_password")

HEADERS = {"Content-Type": "application/json", "Accept": "application/json"}
ST_CHG_TEMPLATE = ''  # 1.Get the standard change template ID
ST_CHG_TEMP_URL = ''  # 2. URL for POST request to create a change from standard template
ST_CHG_URL = ''
ST_CHG_TASK_URL = ''

timing = datetime.now().strftime("%Y-%m-%d %H-%M-%s")
logging.basicConfig(level=logging.INFO,
                    format="[%(asctime)s] [%(levelname)5s] [%(module)s:%(lineno)s] %(message)s",
                    filename="./logs/snow_chg.log-" + str(timing))


def create_change():
    schedule_start_time = (datetime.now() - timedelta(hours=4)).strftime("%Y-%m-%d %H:%M") + ":00"
    schedule_end_time = (datetime.now() - timedelta(hours=4)).strftime("%Y-%m-%d %H:%M") + ":30"
    change_data = {'short_description': 'SSL cert is due for renewal',
                   'description': 'SSL cert is due for renewal',
                   'start_date': schedule_start_time,
                   'end_date': schedule_end_time,
                   'assigned_to': '',
                   'u_additional_information': 'SSL cert',
                   'u_downtime': 'No'}
    new_change = requests.post(ST_CHG_TEMP_URL, auth=(snow_user, snow_password), headers=HEADERS,
                               data=json.dumps(change_data))
    result = json.loads(new_change.content)['result']
    print(result)
    if new_change.status_code == 200:
        for i, k in result.items():
            if i == 'sys_id':
                sys_id = k['value']
            if i == 'number':
                change_number = k['value']
        return True, sys_id, change_number


def get_change_info(sys_id):
    get_info_change = requests.get(ST_CHG_URL + str(sys_id), auth=(snow_user, snow_password), headers=HEADERS)
    print(json.loads(get_info_change.content))
    if get_info_change.status_code == 200:
        return True


def change_info():
    update_change = requests.get(ST_CHG_URL, auth=(snow_user, snow_password), headers=HEADERS)
    for i in json.loads(update_change.content)['result']:
        print(i)


def schedule_change(sys_id):
    patch_change_data = {'state': 'Scheduled'}
    schedule_chg = requests.patch(ST_CHG_URL + str(sys_id), auth=(snow_user, snow_password), headers=HEADERS,
                                  data=json.dumps(patch_change_data))
    print(json.loads(schedule_chg.content))
    if schedule_chg.status_code == 200:
        return True


def implement_change(sys_id):
    patch_change_data = {'state': 'Implement'}
    implement_chg = requests.patch(ST_CHG_URL + str(sys_id), auth=(snow_user, snow_password), headers=HEADERS,
                                   data=json.dumps(patch_change_data))
    print(json.loads(implement_chg.content))
    if implement_chg.status_code == 200:
        return True


def get_task_info(sys_id):
    get_chg_task = requests.get(ST_CHG_TASK_URL + str(sys_id) + '/task',
                                auth=(snow_user, snow_password), headers=HEADERS)
    result = json.loads(get_chg_task.content)['result']
    for i in result:
        for j, k in i.items():
            if j == 'sys_id':
                task_sys_id = k['value']
                print(task_sys_id)
    if get_chg_task.status_code == 200:
        return True, task_sys_id


def update_implement_task(sys_id, task_id):
    patch_task_data = {'state': '2.0'}
    implement_task = requests.patch(ST_CHG_TASK_URL + str(sys_id) + '/task/' + str(task_id),
                                    auth=(snow_user, snow_password), headers=HEADERS, data=json.dumps(patch_task_data))
    result = json.loads(implement_task.content)['result']
    print(result)
    if implement_task.status_code == 200:
        return True


def update_close_task(sys_id, task_id):
    patch_task_data = {'state': '3.0'}
    close_task = requests.patch(ST_CHG_TASK_URL + str(sys_id) + '/task/' + str(task_id),
                                auth=(snow_user, snow_password), headers=HEADERS, data=json.dumps(patch_task_data))
    result = json.loads(close_task.content)['result']
    print(result)
    if close_task.status_code == 200:
        return True


def close_change(sys_id):
    patch_change_data = {'state': 'Review'}
    close_chg = requests.patch(ST_CHG_URL + str(sys_id), auth=(snow_user, snow_password), headers=HEADERS,
                               data=json.dumps(patch_change_data))
    print(json.loads(close_chg.content))
    if close_chg.status_code == 200:
        return True


def complete_request():

    create_chg = create_change()
    if create_chg[0]:
        schedule_chg = schedule_change(create_chg[1])
        if schedule_chg:
            implement_chg = implement_change(create_chg[1])
            if implement_chg:
                get_task_id = get_task_info(create_chg[1])
                if get_task_id[0]:
                    implement_task = update_implement_task(create_chg[1], get_task_id[1])
                    if implement_task:
                        close_task = update_close_task(create_chg[1], get_task_id[1])
                        if close_task:
                            close_chg = close_change(create_chg[1])
                            if close_chg:
                                print("Change has been completed successfully!!!")
                                return True
