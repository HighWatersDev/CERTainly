import requests
from requests import exceptions
import subprocess
import time
import logging
import json
import os
from datetime import datetime, timedelta
from os.path import join, dirname
from dotenv import load_dotenv

timing = datetime.now().strftime("%d-%m-%Y-%H-%M")
logging.basicConfig(level=logging.INFO,
                    format="[%(asctime)s] [%(levelname)5s] [%(module)s:%(lineno)s] %(message)s",
                    filename="./logs/f5_certmgr.log-" + str(timing))


class F5Cert:
    def __init__(self):

        dotenv_path = join(dirname(__file__), '.env')
        load_dotenv(dotenv_path)
        self.f5_username = os.getenv('f5_username')
        self.f5_password = os.getenv('f5_password')
        self.f5_url = os.getenv('f5_url')
        self.f5_node = os.getenv('f5_node')

    def get_token(self):
        # Receives secure token from BigIQ. The token is used in every API call to BigIQ
        payload = {"Content-Type": "application/json",
                   "username": self.f5_username,
                   "password": self.f5_password}
        try:
            get_secret_token = requests.post(self.f5_url + "/mgmt/shared/authn/login",
                                             data=json.dumps(payload), headers={}, verify=False)
            response = json.loads(get_secret_token.content)
            token = response['token']['token']
            auth_header = {"X-F5-Auth-Token": token}
            logging.info(str(timing) + "Received Auth Token from F5 BigIQ")
            return auth_header
        except requests.exceptions.RequestException as err:
            logging.error("Exception occurred", err, exc_info=True)
            raise SystemExit(err)

    def get_expiring_certs(self, auth_header):
        # Collects all certs managed by F5 BigIQ that are going to expire soon
        try:
            get_cert = requests.get(self.f5_url + '/mgmt/cm/adc-core/working-config/sys/file/ssl-cert',
                                    headers=auth_header, verify=False)
            if get_cert.status_code == 200:
                response = json.loads(get_cert.content)
                expiring_certs = {}
                for i in response['items']:
                    # print(i)
                    try:
                        subject = str(i['subject']).split(",")[0]
                        cert_name = subject.split("=")[1]
                        exp_time_str = i['expirationDateTime'].split("T")[0]
                        exp_time = datetime.strptime(exp_time_str, "%Y-%m-%d").date()
                        cur_time = datetime.today().date() + timedelta(days=30)
                        if ":" in i['serialNumber']:
                            sn = i['serialNumber']
                        else:
                            sn = hex(int(i['serialNumber']))[2:]
                        if exp_time < cur_time:  # Collects all certs that will expire in less than 30 days
                            if "gatech.edu" in cert_name:
                                expiring_certs.update({cert_name: {}})
                                expiring_certs[cert_name]["serialNumber"] = sn
                                expiring_certs[cert_name]["partition"] = i['partition']
                                expiring_certs[cert_name]["selfLink"] = i['selfLink']
                                expiring_certs[cert_name]["id"] = i['id']
                    except Exception as err:
                        print("Can't parse the response because of, ", err, i)
                        pass
                # logging.info(str(timing) + ": ", expiring_certs)
                print("Expiring certs in F5", expiring_certs)
                return True, expiring_certs
            else:
                logging.info(str(timing) + " - " + str(get_cert.status_code) + " - " + str(get_cert.reason))
        except requests.exceptions.RequestException as err:
            logging.error("Exception occurred", err, exc_info=True)
            raise SystemExit(err)

    def upload_cert(self, auth_header, renewed_certs_in_scm, cert_files):
        expiring_certs = F5Cert().get_expiring_certs(F5Cert().get_token())
        dir_path = os.path.dirname(os.path.realpath(__file__))
        renewed_certs = []
        failed_renewal = []
        for i in cert_files:
            file_name = i
            try:
                # Checks if cert .crt file is already in BigIQ /var/config/rest/downloads/ directory
                get_dir_content = subprocess.run(['ssh', '-i', '/Users/user/.ssh/id_rsa',
                                                  'root@' + self.f5_node,
                                                  'ls -A /var/config/rest/downloads/ | grep ' + file_name],
                                                 capture_output=True)
                logging.info(str(timing) + " - Checking F5 directory - " +
                             str(get_dir_content.returncode) + str(get_dir_content.stdout))
            except Exception as err:
                logging.error("Exception occurred", err, exc_info=True)
                break
                # raise SystemExit(err)
            dir_output = get_dir_content.stdout.decode('utf8').rstrip()
            if dir_output == file_name:
                logging.info("File is already found in F5 directory")
                pass
            elif dir_output == '':
                try:
                    cert_to_upload = dir_path + "/certs/" + file_name
                    upload_cert_to_f5 = subprocess.run(['scp', '-i',
                                                        '/Users/user/.ssh/id_rsa', cert_to_upload,
                                                        'root@' + self.f5_node + ':/var/config/rest/downloads/'],
                                                       capture_output=True)  # Uploads file to F5 BigIQ
                    return_code = upload_cert_to_f5.returncode
                    logging.info(str(timing) + " - Checking status of cert upload - " + str(return_code))
                    if return_code == 0:
                        check_file_dir = subprocess.run(['ssh', '-i', '/Users/user/.ssh/id_rsa',
                                                         'root@' + self.f5_node,
                                                         'ls -A /var/config/rest/downloads/ | grep ' + file_name],
                                                        capture_output=True)  # Checks if the upload succeeded
                        logging.info(str(timing) + " - Checking F5 dir after cert upload - " +
                                     str(check_file_dir.returncode))
                        if check_file_dir.stdout.decode('utf8').rstrip() == file_name:
                            logging.info(str(timing) + "SSL cert is in BigIQ directory")
                except Exception as err:
                    logging.error("Exception occurred", err, exc_info=True)
                    # raise SystemExit(err)
            try:
                for cert in expiring_certs:
                    # Iterates through the list of expiring certs on F5 and renews one by one
                    for cert2 in renewed_certs_in_scm:
                        if cert == cert2 and renewed_certs_in_scm[cert2]['renewed'] is True:
                            self_link = expiring_certs[cert]['selfLink']
                            payload = {
                                       "filePath": "/var/config/rest/downloads/" + file_name,
                                       "certReference": {"link": self_link},
                                       "command": "REPLACE_CERT"
                                      }
                            upload_cert = requests.post(self.f5_url + "/mgmt/cm/adc-core/tasks/certificate-management",
                                                        headers=auth_header, data=json.dumps(payload), verify=False)
                            logging.info(str(timing) + " - Uploading cert to F5 BigIQ " + str(upload_cert.status_code))
                            response = json.loads(upload_cert.content)
                            task_id = response['id']
                            task_status = response['status']
                            # Once the cert is uploaded via API, its initial status is set to "STARTED".
                            # After some time it changes to "FINISHED" if successful
                            if task_status == 'STARTED':
                                time.sleep(20)
                                check_status = requests.get(
                                    self.f5_url + "/mgmt/cm/adc-core/tasks/certificate-management/" +
                                    str(task_id), headers=auth_header, verify=False
                                )
                                new_status = (json.loads(check_status.content))['status']
                                if new_status != 'FINISHED':
                                    logging.error("Certificate failed to upload to F5")
                                    failed_renewal.append(expiring_certs[cert]['id'])
                                elif new_status == 'FINISHED':
                                    renewed_certs.append(expiring_certs[cert]['id'])
                                    logging.info(str(timing) + " - Uploaded cert to F5 BigIQ - " + str(new_status))
                                # Here it checks second time after 20 seconds if the cert was successfully renewed
            except Exception as err:
                logging.error("Exception occurred", err, exc_info=True)
                pass
        return True, renewed_certs, failed_renewal

    def deploy_config(self, auth_header, renewed_certs):
        coda_ltm01 = "https://localhost/mgmt/shared/resolver/device-groups/cm-adccore-allbigipDevices/" \
                     "devices/<#####>"
        coda_ltm02 = "https://localhost/mgmt/shared/resolver/device-groups/cm-adccore-allbigipDevices/" \
                     "devices/<#####>"
        bcdc_ltm01 = "https://localhost/mgmt/shared/resolver/device-groups/cm-adccore-allbigipDevices/" \
                     "devices/<#####>"
        bcdc_ltm02 = "https://localhost/mgmt/shared/resolver/device-groups/cm-adccore-allbigipDevices/" \
                     "devices/<#####>"
        objects_to_deploy = []
        for cert_id in renewed_certs:
            try:
                get_selflink = requests.get(self.f5_url + '/mgmt/cm/adc-core/working-config/sys/file/ssl-cert/' +
                                            str(cert_id), headers=auth_header, verify=False)
                cert_selflink = json.loads(get_selflink.content)['selfLink']
                link_ref = {'link': cert_selflink}
                objects_to_deploy.append(link_ref)
            except Exception as err:
                logging.error("Exception occurred", err, exc_info=True)
        payload = {
            "name": "deploying ssl cert",
            "deviceReferences": [
               {
                "link": coda_ltm01
               },
               {
                "link": coda_ltm02
               },
               {
                "link": bcdc_ltm01
               },
               {
                "link": bcdc_ltm02
               }
            ],
            "skipDistribution": False,
            "reevaluate": False,
            "skipVerifyConfig": True,
            "refreshSharedConfig": True,
            "objectsToDeployReferences": objects_to_deploy,
            "deploySpecifiedObjectsOnly": True,
            "skipCurrentConfigRefresh": True,
            "partialModeEnableDeletedObjectRemoval": True
        }
        try:
            f5_deploy = requests.post(self.f5_url + '/mgmt/cm/adc-core/tasks/deploy-configuration',
                                      headers=auth_header, data=json.dumps(payload), verify=False)
            deployment_status = json.loads(f5_deploy.content)['status']
            deployment_id = json.loads(f5_deploy.content)['id']
            if deployment_status == 'STARTED':
                time.sleep(30)
                check_status = requests.get(self.f5_url + '/mgmt/cm/adc-core/tasks/deploy-configuration/' +
                                            str(deployment_id), headers=auth_header, verify=False)
                new_deployment_status = json.loads(check_status.content)['id']
                if new_deployment_status != "FINISHED":
                    logging.error("Exception occurred", exc_info=True)
        except Exception as err:
            logging.error("Exception occurred", err, exc_info=True)
            raise SystemExit(err)
        return True
