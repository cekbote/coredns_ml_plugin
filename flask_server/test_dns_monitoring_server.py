import unittest
import numpy as np
from datetime import datetime
from elasticsearch import Elasticsearch
from .dns_monitoring_server import *


class TestDNSMonitoringServer(unittest.TestCase):

    def setUp(self):
        self.es = Elasticsearch()

    def test_string_to_ascii(self):
        num_array = string_to_ascii('google.com')
        test_array = np.asarray([103., 111., 111., 103., 108., 101.,
                                 46., 99., 111., 109.])
        data = {'Domain name': 'google.com', 'IP': '127.12.12.32'}
        self.assertEqual(num_array.tolist(), test_array.tolist())

    def test_mal_and_benign_list_creation(self):
        try:
            mal_and_benign_list_creation(self.es)
            if 'mal' in self.es.indices.get('*') and \
                    'benign' in self.es.indices.get('*'):
                check = True
            else:
                check = False
            self.assertTrue(check, 'Error: mal and benign list creation')
        except:
            self.fail('Error: Elasticsearch Server')

    def test_vetted_list_creation(self):
        try:
            vetted_list_creation(self.es)
            if 'not_vetted' in self.es.indices.get('*') and \
                    'benign_vet' in self.es.indices.get('*') and \
                    'honeypot' in self.es.indices.get('*') and \
                    'blacklist' in self.es.indices.get('*'):
                check = True
            else:
                check = False
            self.assertTrue(check, 'Error: vetted list creation')
        except:
            self.fail('Error: Elasticsearch Server')

    def test_list_updation(self):
        dn_benign = 'test_benign.com'
        send_benign = '0.49'
        dn_mal = 'test_mal.com'
        send_mal = '0.51'
        check_benign = False
        check_mal = False
        check_not_vet = False

        try:
            list_updation(self.es, dn_benign, send_benign)
            list_updation(self.es, dn_mal, send_mal)
            benign_metadata = \
                self.es.get(index='benign', id=1)['_source'][dn_benign]
            mal_metadata = self.es.get(index='mal', id=1)['_source'][dn_mal]
            not_vetted = self.es.get(index='not_vetted', id=1)['_source']
            if benign_metadata['count'] >= 1 and \
                    benign_metadata['status'] > 50:
                check_benign = True
            if mal_metadata['count'] >= 1 and \
                    mal_metadata['status'] > 50:
                check_mal = True
            if dn_mal in not_vetted.keys() and dn_benign in not_vetted.keys():
                check_not_vet = True
            self.assertTrue(check_benign, 'Error: benign list')
            self.assertTrue(check_mal, 'Error: malicious list')
            self.assertTrue(check_not_vet, 'Error: not vetted list')

        except:
            self.fail('Error: Elasticsearch Server')

    def test_update_historical_analysis(self):
        domain_name = 'test_domain.com'
        date_time = datetime.now()
        ip = '127.23.12.32'
        send = '0.55'

        try:
            update_historical_analysis(self.es, domain_name, ip, send,
                                       date_time)

            date = str(date_time.date())
            year = str(date_time.date().year)
            month = str(date_time.date().month)
            day = str(date_time.date().day)
            hour = str(date_time.time().hour)
            minutes = str(date_time.time().minute)

            check_creation = False

            body = self.es.get(index=domain_name, id=1)['_source']
            if date in body.keys() and year in body.keys() and 'status' in \
                    body.keys() and 'count' in body.keys():
                check_creation = True

            self.assertTrue(check_creation, 'Error: historical analysis'
                                            'creation failed')

        except:
            self.fail('Error: Elasticsearch Server')


if '__name__' == '__main__':
    unittest.main()
