import dash
import dash_core_components as dcc
import dash_html_components as html
from datetime import datetime as dt
import dash_table
import dash_daq as daq
from dash.dependencies import Input, Output, State
import copy
from elasticsearch import Elasticsearch
import numpy as np
import unittest
import os
from .malicious_domain_name_analysis import *
from unittest import mock


class TestMaliciousDomainNameAnalysis(unittest.TestCase):

    def setUp(self):
        self.es = Elasticsearch()

    def test_input_message(self):
        message_none = input_message(1, None)
        message_domain_name = input_message(1, 'google.com')
        message_not_existed = input_message(1, 'not_exist')
        self.assertEqual(message_none, 'Please enter a Domain Name')
        self.assertEqual(message_domain_name, 'You have entered: google.com')
        self.assertEqual(message_not_existed, 'Domain Name does not exist in '
                                              'Database')


if '__name__' == '__main__':
    unittest.main()