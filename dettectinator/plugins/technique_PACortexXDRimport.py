from plugins.technique_import import TechniqueBase
from argparse import ArgumentParser
from collections.abc import Iterable

from argparse import ArgumentParser
from collections.abc import Iterable
import json
import os
import sys
import re
import requests
import urllib3

import pandas as pd
import hashlib
import random
import string
import time

try:
    # When dettectinator is installed as python library
    from dettectinator.plugins.support.authentication import Azure, Tanium
except ModuleNotFoundError:
    # When dettectinator is not installed as python library
    sys.path.append(os.path.dirname(os.path.abspath(__file__).replace('plugins', '')))
    from plugins.support.authentication import Azure, Tanium


# Disable SSL certificate warnings for dev purposes:
urllib3.disable_warnings()
    
class TechniquePACortexXDR(TechniqueBase):
    """
    Import alert data from PaloAlto Cortex XDR Alert API (IOC and BIOC)
    """

    def __init__(self, parameters: dict) -> None:
        super().__init__(parameters)

        if 'app_id' not in self._parameters:
            raise Exception('TechniquePACortexXDR: "app_id" parameter is required.')

        if 'secret' not in self._parameters:
            raise Exception('TechniquePACortexXDR: "secret" parameter (api_key) is required.')

        if 'workspace' not in self._parameters:
            raise Exception('TechniquePACortexXDR: "workspace" parameter is required.')

        self._app_id = self._parameters['app_id']
        self._secret = self._parameters['secret']
        self._workspace = self._parameters['workspace']

    @staticmethod
    def get_cortex_api_key_hash(api_key, nonce, timestamp) -> str:
        auth_key = api_key + nonce + str(timestamp)
        hasher = hashlib.sha256()
        hasher.update(auth_key.encode('utf-8'))
        return hasher.hexdigest()

    def get_nonce(self) -> int:
        length=64
        characters = string.ascii_letters + string.digits
        return ''.join(random.choice(characters) for _ in range(length))

    def set_xdr_api_headers(self) -> str :
        timestamp = int(time.time()) * 1000
        nonce = self.get_nonce()
        appid = self._app_id
        api_keyhash = self.get_cortex_api_key_hash(self._secret, nonce, timestamp)

        headers = {
            'x-xdr-timestamp': str(timestamp),
            'x-xdr-nonce': nonce,
            'x-xdr-auth-id': appid,
            'Authorization': api_keyhash,
            'Accept-Encoding': 'gzip, deflate'
        }
        
        return headers


    def set_plugin_params(parser: ArgumentParser) -> None:
        """
        Set command line arguments specific for the plugin
        :param parser: Argument parser
        """
        TechniqueBase.set_plugin_params(parser)

        parser.add_argument('--app_id', help='Cortex XDR AppID', required=True)
        parser.add_argument('--secret', help='Cortex XDR secret (API Key)', required=True)
        parser.add_argument('--workspace', help='Cortex XDR workspace URL', required=True)

    def get_data_from_source(self) -> Iterable:
        """
         Gets the use-case/technique data from the source.
         :return: Iterable, yields technique, detection, applicable_to
         """
        cortex_data = self._get_pa_cortex_xdr_data()

        for index, record in cortex_data.iterrows():
            technique = record['technique']
            use_case = record['description']
            yield technique, use_case, None

    def build_query(self,offset) :
        return '"search_from" : ' + str(offset) + ', \
            "search_to" : ' + str(offset+100) + ', \
           "filters" : [ { \
            "field" : "alert_source", \
            "value" : [\"XDR Analytics\",\"XDR Analytics BIOC\"], \
            "operator" : "in" \
            } \
           ]'

    def _get_pa_cortex_xdr_data(self) -> list:
        """
        Collect the alerts on Cortex XDR
        """
        url = f'https://{self._workspace}/alerts/get_alerts/'
        headers = self.set_xdr_api_headers()

        offset = 0
        query = self.build_query(offset)

        payload = '{\"request_data\": {' + query + '} }'
        
        response = requests.post(url, data = payload, headers=headers).json()

        count = response['reply']['total_count']
        returned = response['reply']['result_count']
        print('Data size : '+ str(count) + ' got ' + str(returned))

        alerts = pd.DataFrame() # empty frame
        alerts = pd.json_normalize(response['reply']['alerts'])

        # Get the rest of the data in chunks of 100

        n_sweeps = (count // 100) + 1
        print('Need to get ' + str(n_sweeps-1) + ' additional chunks')

        for i in range(n_sweeps-1) :
#          reset the key every 10 fetches; the timeout is 5 minutes and the interface is slow
           if (i % 10 == 0) : 
               headers = headers = self.set_xdr_api_headers()

           offset = (i+1) * 100
           query = self.build_query(offset)
           payload = '{\"request_data\": {' + query + '} }'
           response = requests.post(url, data = payload, headers=headers).json()
           progress = ((i+1)/n_sweeps)*100
           print('Progress : ' + str(i + 1) + " :  {0:0.2f}%".format(round(progress, 2)))
           tempdata = pd.json_normalize(response['reply']['alerts'])
           alerts = pd.concat([alerts, tempdata], ignore_index = True)

        temp1 = alerts.explode('mitre_tactic_id_and_name')
        temp1[['tactic', 'tactic_name']] = temp1['mitre_tactic_id_and_name'].str.split(pat = ' - ', expand=True)
        temp1.drop(['mitre_tactic_id_and_name'], axis = 1, inplace = True)

        temp2 = temp1.explode('mitre_technique_id_and_name')
        temp2[['technique', 'technique_name']] = temp2['mitre_technique_id_and_name'].str.split(pat = ' - ', expand=True)
        temp2.drop(['mitre_technique_id_and_name'], axis = 1, inplace = True)

        # Get only unique techniques and concatenate all use cases separated with a ;
        alldata = temp2[['technique','description']].copy()

        return alldata