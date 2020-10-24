import requests
import os
import json
import logging
import time
from os.path import join, dirname
from dotenv import load_dotenv
from datetime import datetime, timedelta


timing = datetime.now().strftime("%d-%m-%Y-%H-%M")
logging.basicConfig(level=logging.INFO,
                    format="[%(asctime)s] [%(levelname)5s] [%(module)s:%(lineno)s] %(message)s",
                    filename="./logs/scm_certmgr.log-" + str(timing))


class ScmSsl:
    def __init__(self):
        dotenv_path = join(dirname(__file__), '.env')
        load_dotenv(dotenv_path)
        self.scm_username = os.getenv('scm_username')
        self.scm_password = os.getenv('scm_password')

    def get_cert_scm(self, expiring_certs):
        url = "https://cert-manager.com/api/ssl/v1"
        payload = {}
        headers = {'login': self.scm_username, 'Content-Type': 'application/json',
                   'password': self.scm_password,
                   'customerUri': 'InCommon'
                   }
        certs_in_scm = {}
        ssl_ids = []
        # pulls list of expiring certs from F5 BigIQ
        # print(expiring_certs_f5)
        for cert in expiring_certs:
            sn = expiring_certs[cert]['serialNumber']
            # locates the info about the cert from InCommon
            list_cert = url + "?serialNumber=" + str(sn)
            try:
                response = requests.get(list_cert, headers=headers, data=payload)
                if response.status_code == 200:
                    parsed = json.loads(response.content)
                    for i in parsed:
                        # collects IDs of each cert to use for further operations
                        ssl_ids.append(i['sslId'])
                        logging.info(str(timing) + " Corresponding cert in SCM - " + str(i['commonName']))
            except requests.exceptions.RequestException as err:
                logging.error("Exception occurred", err, exc_info=True)
                pass
                # raise SystemExit(err)
        for cert_id in ssl_ids:
            cert_url = url + "/" + str(cert_id)
            try:
                get_cert_info = requests.get(cert_url, headers=headers, data=payload)
                cert_info = json.loads(get_cert_info.content)
                # Gets full information about certificate from Sectigo
                logging.info(str(timing) + " - Getting cert info - " + str(get_cert_info.status_code))
                # Get detailed information about the cert including commonName, SAN, etc
                if get_cert_info.status_code == 200:
                    # Creates nested dictionary to use in further operations in form
                    # {cert_name: {'sslid': #, 'expiration': #}}
                    name = cert_info['commonName']
                    certs_in_scm.update({name: {}})
                    certs_in_scm[name]["sslId"] = cert_info['sslId']
                    # certs_in_scm[name]["expiration"] = cert_info['expires']
            except requests.exceptions.RequestException as err:
                logging.error("Exception occurred", err, exc_info=True)
                pass
                # raise SystemExit(err)
        logging.info(str(timing) + " - Finished collecting certs in SCM")
        print(certs_in_scm)
        return True, certs_in_scm

    def renew_cert_scm(self, certs_in_scm):
        check_status_url = 'https://cert-manager.com/api/ssl/v1/'
        url = "https://cert-manager.com/api/ssl/v1/renewById/"
        collect_url = "https://cert-manager.com/api/ssl/v1/collect/"
        headers = {'login': self.scm_username, 'Content-Type': 'application/json',
                   'password': self.scm_password,
                   'customerUri': 'InCommon'
                   }
        payload = {}
        ssl_type = "pemco" # this format allows for easier conversion to .crt file
        ssl_chain_type = "x509IOR"
        new_ssl_ids = []
        file_list = []
        chain_file_list = []
        renewed_certs_in_scm = certs_in_scm
        dir_path = os.path.dirname(os.path.realpath(__file__))
        # Referring to the dictionary of expiring certs and associated IDs
        for cert, cert_details in certs_in_scm.items():
            ssl_id = cert_details['sslId']
            try:
                cert_renew = requests.post(url + str(ssl_id), headers=headers, data=payload)
                logging.info(str(timing) + " - " + str(cert_renew.content))
                if cert_renew.status_code != 200:
                    logging.error("Exception occurred", cert_renew.reason, exc_info=True)
                elif cert_renew.status_code == 200:
                    new_ssl_id = json.loads(cert_renew.content)['sslId']
                    new_ssl_ids.append(new_ssl_id)
                    renewed_certs_in_scm[cert]['sslId'] = new_ssl_id
                    check_status = requests.get(check_status_url + str(new_ssl_id), headers=headers, data=payload)
                    status_response = json.loads(check_status.content)
                    print("Cert status after renewal: ", status_response['status'])
                    if status_response['status'] != 'Issued':
                        time.sleep(30)
                    else:
                        continue
                    check_status2 = requests.get(check_status_url + str(new_ssl_id), headers=headers,
                                                 data=payload)
                    print(json.loads(check_status2.content)['status'])
                    if json.loads(check_status2.content)['status'] == 'Issued':
                        renewed_certs_in_scm[cert]["renewed"] = True
                        # Once the cert is renewed, we are provided with new ID for the renewed cert
                        # Requesting cert as .cer PEM encoded in format ------BEGIN CERTIFICATE------
                        print("Collecting cert")
                        collect_cert = requests.get(collect_url + str(new_ssl_id) + "/" + ssl_type, headers=headers,
                                                    data=payload)
                        logging.info(str(timing) + " - collecting cert " + str(collect_cert.status_code))
                        collect_cert_chain = requests.get(collect_url + str(new_ssl_id) + "/" + ssl_chain_type,
                                                          headers=headers, data=payload)
                        logging.info(str(timing) + " - collecting cert chain " + str(collect_cert_chain.status_code))
                        print(json.loads(collect_cert.reason))
                        print(collect_cert.status_code)
                        if collect_cert.status_code == 200:
                            encoded_cert = collect_cert.content
                            cert_file_name = cert.replace(".", "_") + ".crt"  # Uses cert name as .crt file name
                            try:
                                # Writing the cert to a file to then upload it to F5 BigIQ
                                with open(dir_path + "/certs/" + cert_file_name, "wb") as cert_file:
                                    cert_file.write(encoded_cert)
                                file_list.append(cert_file_name)
                                renewed_certs_in_scm[cert]["fileName"] = cert_file_name
                                print(certs_in_scm[cert]['fileName'])
                                logging.info(str(timing) + " - Writing certs to file")
                            except requests.exceptions.RequestException as err:
                                logging.error("Exception occurred", err, exc_info=True)
                                pass
                                # raise SystemExit(err)
                        if collect_cert_chain.status_code == 200:
                            encoded_cert_chain = collect_cert_chain.content
                            cert_chain_file_name = cert.replace(".", "_") + "_chain.crt"  # Uses cert name as .crt file name
                            try:
                                # Writing the cert chain to a file
                                with open(dir_path + "/certs/" + cert_chain_file_name, "wb") as cert_file:
                                    cert_file.write(encoded_cert_chain)
                                chain_file_list.append(cert_chain_file_name)
                                renewed_certs_in_scm[cert]["fileChainName"] = cert_chain_file_name
                                print(certs_in_scm[cert]['fileName'])
                                logging.info(str(timing) + " - Writing certs chain to file")
                            except requests.exceptions.RequestException as err:
                                logging.error("Exception occurred", err, exc_info=True)
                                pass
                    else:
                        renewed_certs_in_scm[cert]["renewed"] = False
                        logging.info(str(timing) + json.loads(check_status2.content)['commonName'] + " : " +
                                     json.loads(check_status2.content)['status'])
            except requests.exceptions.RequestException as err:
                logging.error("Exception occurred", err, exc_info=True)
                pass
                # raise SystemExit(err)
        return True, renewed_certs_in_scm, file_list, chain_file_list

    def report_expiring_ssl(self):
        url = "https://cert-manager.com/api/report/v1/ssl-certificates"
        headers = {'login': self.scm_username, 'Content-Type': 'application/json;charset=utf-8',
                   'password': self.scm_password,
                   'customerUri': 'InCommon'
                   }
        today = datetime.today().date()
        target_date = today + timedelta(days=30)
        data_from = str(today) + "T00:00:00.000Z"
        data_to = str(target_date) + "T00:00:00.000Z"
        new_payload = {"from": data_from, "to": data_to, "organizationIds": [], "certificateStatus": 2,
                       "certificateDateAttribute": 3, "serialNumberFormat": ""}
        try:
            report = requests.post(url, headers=headers, json=new_payload)
            if report.status_code == 200:
                report_result = json.loads(report.content)
                for i in report_result['reports']:
                    print(i)
        except requests.exceptions.RequestException as err:
            logging.error("Exception occurred", err, exc_info=True)
