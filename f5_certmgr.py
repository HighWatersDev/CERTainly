import requests
from requests import exceptions
import subprocess
import time
import logging
import json
import os
from datetime import datetime, timedelta


class F5Cert:
    def __init__(self):
        try:
            with open('creds.json', 'r') as cred_file:
                creds = json.load(cred_file)
                self.f5_username = creds['f5_username']
                self.f5_password = creds['f5_password']
                self.f5_url = creds['f5_url']
                self.f5_node = creds['f5_node']
        except IOError as err:
            logging.error("Exception occurred", err, exc_info=True)
            raise SystemExit(err)
        time = datetime.now().strftime("%d-%m-%Y-%H-%M")
        logging.basicConfig(level=logging.INFO,
                            format="[%(asctime)s] [%(levelname)5s] [%(module)s:%(lineno)s] %(message)s",
                            filename="f5_certmgr.log" + str(time))

    def get_token(self):
        payload = {"Content-Type": "application/json",
                   "username": self.f5_username,
                   "password": self.f5_password}
        try:
            get_secret_token = requests.post(self.f5_url + "/mgmt/shared/authn/login",
                                             data=json.dumps(payload), headers={}, verify=False)
            response = json.loads(get_secret_token.content)
            token = response['token']['token']
            auth_header = {"X-F5-Auth-Token": token}
            return auth_header
        except requests.exceptions.RequestException as err:
            logging.error("Exception occurred", err, exc_info=True)
            raise SystemExit(err)

    def get_expiring_certs(self, auth_header):
        try:
            get_cert = requests.get(self.f5_url + '/mgmt/cm/adc-core/working-config/sys/file/ssl-cert',
                                    headers=auth_header, verify=False)
            response = json.loads(get_cert.content)
            expiring_certs = {}
            san = "SAN"
            partition = "partition"
            link = "selfLink"
            for i in response['items']:
                try:
                    subject = str(i['subject']).split(",")[0]
                    cert_name = subject.split("=")[1]
                    exp_time_str = i['expirationDateTime'].split("T")[0]
                    exp_time = datetime.strptime(exp_time_str, "%Y-%m-%d").date()
                    cur_time = datetime.today().date() + timedelta(days=30)
                    if exp_time < cur_time:
                        if "gatech.edu" in cert_name:
                            expiring_certs.update({cert_name: {}})
                            expiring_certs[cert_name][san] = i['subjectAlternativeName']
                            expiring_certs[cert_name][partition] = i['partition']
                            expiring_certs[cert_name][link] = i['selfLink']
                except:
                    pass
            return expiring_certs
        except requests.exceptions.RequestException as err:
            logging.error("Exception occurred", err, exc_info=True)
            raise SystemExit(err)

    def upload_cert(self, auth_header, file_name):
        expiring_certs = certs.get_expiring_certs(certs.get_token())
        dir_path = os.path.dirname(os.path.realpath(__file__))
        try:
            get_dir_content = subprocess.run(['ssh', '-i', '/home/certapi/.ssh/id_rsa', 'root@' + self.f5_node,
                                              'ls -A /var/config/rest/downloads/ | grep ' + file_name],
                                             capture_output=True)
        except Exception as err:
            logging.error("Exception occurred", err, exc_info=True)
            raise SystemExit(err)
        dir_output = get_dir_content.stdout.decode('utf8').rstrip()
        if dir_output == file_name:
            logging.info("File is already found in F5 directory")
            raise SystemExit
        elif dir_output == '':
            try:
                cert_to_upload = dir_path + "/certs/" + file_name
                upload_cert_to_f5 = subprocess.run(['scp', '-i', '/home/certapi/.ssh/id_rsa', cert_to_upload,
                                                    'root@' + self.f5_node + ':/var/config/rest/downloads/'],
                                                   capture_output=True)
                return_code = upload_cert_to_f5.returncode
                if return_code == 0:
                    check_file_dir = subprocess.run(['ssh', '-i', '/home/certapi/.ssh/id_rsa',
                                                     'root@' + self.f5_node,
                                                     'ls -A /var/config/rest/downloads/ | grep ' + file_name],
                                                    capture_output=True)
                    if check_file_dir.stdout.decode('utf8').rstrip() == file_name:
                        return True
            except Exception as err:
                logging.error("Exception occurred", err, exc_info=True)
                raise SystemExit(err)
        try:
            for i in expiring_certs:
                self_link = expiring_certs[i]['selfLink']
                payload = {
                           "filePath": "/var/config/rest/downloads/" + file_name,
                           "certReference": {"link": self_link},
                           "command": "REPLACE_CERT"
                          }
                upload_cert = requests.post(self.f5_url + "/mgmt/cm/adc-core/tasks/certificate-management",
                                            headers=auth_header, data=json.dumps(payload), verify=False)
                response = json.loads(upload_cert.content)
                task_id = response['id']
                task_status = response['status']
                if task_status == 'STARTED':
                    time.sleep(20)
                    check_status = requests.get(
                        self.f5_url + "/mgmt/cm/adc-core/tasks/certificate-management/" +
                        str(task_id), headers=auth_header, verify=False
                    )
                    new_status = (json.loads(check_status.content))['status']
                    if new_status != 'FINISHED':
                        logging.error("Certificate failed to upload to F5")
                        raise SystemExit()

        except Exception as err:
            logging.error("Exception occurred", err, exc_info=True)
            raise SystemExit(err)
        recheck_expiring_certs = certs.get_expiring_certs(certs.get_token())
        if recheck_expiring_certs != {}:
            logging.error("Not all certificates were renewed", recheck_expiring_certs)
            raise
        return True


certs = F5Cert()



