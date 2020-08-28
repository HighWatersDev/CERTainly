import requests
import os
import json
import logging
from datetime import datetime, timedelta
from SSL.f5_certmgr import F5Cert


class ScmSsl:
    def __init__(self):
        try:
            with open('creds.json', 'r') as cred_file:
                creds = json.load(cred_file)
                self.scm_username = creds['scm_username']
                self.scm_password = creds['scm_password']
        except IOError as err:
            logging.error("exception occur: ", err, exc_info=True)
            raise SystemError(err)
        time = datetime.now().strftime("%d-%m-%Y-%H-%M")
        logging.basicConfig(level=logging.INFO,
                            format="[%(asctime)s] [%(levelname)5s] [%(module)s:%(lineno)s] %(message)s",
                            filename="scm_certmgr.log" + str(time))

    def get_cert_scm(self, expiring_cert_f5):
        url = "https://cert-manager.com/api/ssl/v1"
        payload = {}
        headers = {'login': self.scm_username, 'Content-Type': 'application/json',
                   'password': self.scm_password,
                   'customerUri': 'InCommon'
                   }
        certs_in_scm = {}
        ssl_ids = []
        #pulls list of expiring certs from F5 BigIQ
        for cert in expiring_cert_f5:
            #locates the info about the cert from InCommon
            list_cert = url + "?commonName=" + str(cert)
            try:
                response = requests.get(list_cert, headers=headers, data=payload)
                if response.status_code == 200:
                    parsed = json.loads(response.content)
                    for i in parsed:
                        if i['commonName'] == cert:
                            #collects IDs of each cert to use for further operations
                            ssl_ids.append(i['sslId'])
            except requests.exceptions.RequestException as err:
                logging.error("Exception occurred", err, exc_info=True)
                raise SystemExit(err)
        for cert_id in ssl_ids:
            cert_url = url + "/" + str(cert_id)
            try:
                get_cert_info = requests.get(cert_url, headers=headers, data=payload)
                cert_info = json.loads(get_cert_info.content)
                #Get detailed information about the cert including commonName, SAN, etc
            except requests.exceptions.RequestException as err:
                logging.error("Exception occurred", err, exc_info=True)
                raise SystemExit(err)
            if get_cert_info.status_code == 200:
                #We only care about Issued certs filtering out expired and revoked
                if cert_info['status'] == 'Issued':
                    #In case there are multiple certs with the same name, we find the one the has the same SAN
                    if 'subjectAlternativeNames' in cert_info:
                        for cert_in_dict in expiring_cert_f5:
                            san = expiring_cert_f5[cert_in_dict]['SAN']
                            if cert_info['subjectAlternativeNames'] == san:
                                name = cert_info['commonName']
                                certs_in_scm.update({name: {}})
                                certs_in_scm[name]["sslId"] = cert_info['sslId']
                                certs_in_scm[name]["expiration"] = cert_info['expires']
                    elif 'subjectAlternativeNames' not in cert_info:
                        name = cert_info['commonName']
                        certs_in_scm.update({name: {}})
                        certs_in_scm[name]["sslId"] = cert_info['sslId']
                        certs_in_scm[name]["expiration"] = cert_info['expires']
        print(certs_in_scm)
        return certs_in_scm

    def renew_cert_scm(self, certs_in_scm):
        url = "https://cert-manager.com/api/ssl/v1/renewById/"
        collect_url = "https://cert-manager.com/api/ssl/v1/collect/"
        headers = {'login': self.scm_username, 'Content-Type': 'application/json',
                   'password': self.scm_password,
                   'customerUri': 'InCommon'
                   }
        payload = {}
        ssl_type = "pemco" #this format allows for easier conversion to .crt file
        new_ssl_ids = []
        file_list = []
        dir_path = os.path.dirname(os.path.realpath(__file__))
        #Referring to the dictionary of expiring certs and associated IDs
        for cert in certs_in_scm:
            for cert_id in certs_in_scm[cert]:
                ssl_id = certs_in_scm[cert][cert_id]
                try:
                    cert_renew = requests.post(url + str(ssl_id), headers=headers, data=payload)
                    if cert_renew.status_code == 200:
                        new_ssl_id = json.loads(cert_renew.content)['sslId']
                        new_ssl_ids.append(new_ssl_id)
                        #Once the cert is renewed, we are provided with new ID for the renewed cert
                        #Requesting cert as .cer PEM encoded in format ------BEGIN CERTIFICATE------
                        collect_cert = requests.get(collect_url + str(new_ssl_id) + ssl_type, headers=headers,
                                                    data=payload)
                        if collect_cert.status_code == 200:
                            encoded_cert = collect_cert.content
                            cert_file_name = cert.replace(".", "_") + ".crt"
                            try:
                                #Writing the cert to a file to then upload it to F5 BigIQ
                                with open(dir_path + "/certs/" + cert_file_name, "wb") as cert_file:
                                    cert_file.write(encoded_cert)
                                file_list.append(cert_file_name)
                            except requests.exceptions.RequestException as err:
                                logging.error("Exception occurred", err, exc_info=True)
                                raise SystemExit(err)
                except requests.exceptions.RequestException as err:
                    logging.error("Exception occurred", err, exc_info=True)
                    raise SystemExit(err)
        for crt_file in file_list:
            upload_cert_to_f5 = expiring_cert_f5.upload_cert(expiring_cert_f5.get_token(), crt_file)
            if upload_cert_to_f5 is True:
                return True

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
            raise SystemExit(err)


expiring_cert_f5 = F5Cert()
t1 = ScmSsl()
t1.get_cert_scm(expiring_cert_f5.get_expiring_certs(expiring_cert_f5.get_token()))
t1.report_expiring_ssl()
