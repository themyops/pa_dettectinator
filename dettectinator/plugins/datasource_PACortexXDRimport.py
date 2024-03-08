from plugins.datasources_import import DatasourceBase, DatasourceOssemBase
from argparse import ArgumentParser
from collections.abc import Iterable

import pandas as pd
import requests
import hashlib
import random
import string
import time
import zlib
import io

class DatasourcePACortexXDR(DatasourceOssemBase):
    """
    PaloAlto Cortex XDR  Datasource import
    """

    def __init__(self, parameters: dict) -> None:
        super().__init__(parameters)

        if 'app_id' not in self._parameters:
            raise Exception('DatasourcePACortexXDR: "app_id" parameter is required.')

        if 'secret' not in self._parameters:
            raise Exception('DatasourcePACortexXDR: "secret" parameter (api_key) is required.')

        if 'workspace' not in self._parameters:
            raise Exception('DatasourcePACortexXDR: "workspace" parameter is required.')

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
        # DatasourceBase.set_plugin_params(parser) - not (yet) implemented

        parser.add_argument('--app_id', help='Cortex XDR AppID', required=True)
        parser.add_argument('--secret', help='Cortex XDR secret (API Key)', required=True)
        parser.add_argument('--workspace', help='Cortex XDR workspace URL', required=True)

    def get_data_from_source(self) -> Iterable:
        """
         Gets the detectected EventlogID data from the source to determine events that are detected
         :return: Iterable, yields technique, detection, applicable_to
         """
        cortex_data = self._get_pa_cortex_xdr_data()

        for index, record in cortex_data.iterrows():
            datasource = record['datasource']
            product = record['product']
            yield datasource, product, None

    def _get_pa_cortex_xdr_data(self) -> list:
        """
        Collect the event codes from the eventlog on Cortex XDR
        """
        url = f'https://{self._workspace}/xql/start_xql_query'

        headers = self.set_xdr_api_headers()

        query = 'config case_sensitive = false \
            | dataset = xdr_data \
            | filter event_type = ENUM.EVENT_LOG \
            | comp count(action_evtlog_event_id) as evtnumber by action_evtlog_event_id \
            | sort desc evtnumber \
            | fields evtnumber, action_evtlog_event_id'

        # Initiate the query and obtain the queryid
        payload = '{\"request_data\": { \"query\" : \"' + query + ' \"} }'
        response = requests.post(url, data = payload, headers = headers).json()
        queryid  = response['reply']

        # Execute the query (only return once the stream is available)
        url = f'https://{self._workspace}/xql/get_query_results'
        payload = "{\"request_data\": { \"query_id\": \"" + str(queryid) + "\", \"pending_flag\": false } }" # only reply once the query has executed, otherwise wait
        response = requests.post(url, data = payload, headers=headers).json()

        try : # assume a large number of results and we obtain a streamid to download the compressed data and decompress on the fly
            streamid = response['reply']['results']['stream_id']
            url = f'https://{self._workspace}/xql/get_query_results_stream'
            payload = "{\"request_data\": { \"stream_id\": \"" + str(streamid) + "\", \"is_gzip_compressed\": true } }"
            response = requests.post(url, data=payload, headers=headers)
            data = zlib.decompress(response.content, zlib.MAX_WBITS|32)
            event_data = pd.read_json(io.StringIO(data.decode(('utf8'))), lines=True)

        except : # We have less than 1000 records and the data is returned to us directly; this will usually be the case in this module 
            event_data = pd.json_normalize(response['reply']['results']['data'])

        event_data['action_evtlog_event_id'] = event_data['action_evtlog_event_id'].astype('int32')

        url = 'https://raw.githubusercontent.com/OTRF/OSSEM-DM/main/use-cases/mitre_attack/attack_events_mapping.csv'
        ossem_data = pd.read_csv(url)
        ossem_data = ossem_data[pd.to_numeric(ossem_data['EventID'], errors='coerce').notnull()]
        ossem_data['EventID'] = ossem_data['EventID'].astype('int32')
        ossem_data.rename(columns = {'Component' : 'datasource'}, inplace = True)

        data_sources = event_data.merge(ossem_data, how = 'inner', left_on = 'action_evtlog_event_id', right_on = 'EventID')
        data_sources['EventID'] = data_sources['EventID'].astype('str')
        data_sources['product'] = data_sources[['Log Source','EventID']].agg(": ".join, axis = 1)

        alldata = data_sources[['datasource','product']].copy()

        return alldata