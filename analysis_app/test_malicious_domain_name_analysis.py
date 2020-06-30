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
        input_message(1, None)
        print('Work')


if '__name__' == '__main__':
    unittest.main()