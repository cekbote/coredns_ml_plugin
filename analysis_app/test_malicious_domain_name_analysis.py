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
import datetime
import unittest
import os
from .malicious_domain_name_analysis import *
from faker import Faker
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

    def test_date_message(self):
        message_none = date_message(1, '', None, None)

        check = False
        random_option = ['Minute', 'Hour', 'Day']
        option = random_option[np.random.randint(0, 3)]
        fake = Faker()
        start_date = datetime.date(year=2020, month=1, day=1)
        end_date = datetime.datetime.now().date()
        date_start = fake.date_between(start_date=start_date, end_date=end_date)
        date_end = fake.date_between(start_date=date_start, end_date=end_date)
        message_option = date_message(1, option, str(date_start), str(date_end))

        if 'Data from' in message_option or 'please enter' in message_option:
            check = True

        self.assertEqual(message_none, 'Please enter the date range')
        self.assertTrue(check)

    def test_radio_button_message(self):
        message_none = radio_button_message(1, None)
        message_option = radio_button_message(1, 'Test_Option')

        self.assertEqual(message_none, 'Please select an option')
        self.assertEqual(message_option, 'You have selected: Test_Option')

    def test_hour_range_message(self):
        message_none = hour_range_message('', None, None)

        random_option = ['Minute', 'Hour']
        random_choice = random_option[np.random.randint(0, 2)]
        start = np.random.randint(0, 24)
        end = np.random.randint(start, 25)
        message_option = hour_range_message(random_choice, start, end)
        check = False

        if 'Hour range' in message_option or 'Please enter' in message_option \
                or 'The difference' in message_option:
            check = True

        self.assertEqual(message_none, 'Enter an integer hour range (0 to 24)')
        self.assertTrue(check)


if '__name__' == '__main__':
    unittest.main()
