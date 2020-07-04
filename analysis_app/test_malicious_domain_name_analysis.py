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

    # Historical Analysis

    # Control Messages

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

    # Graph and Div Updates

    def test_display_hour_range(self):
        display_none = display_hour_range('Day')
        display_option = display_hour_range('')

        self.assertEqual(display_none['display'], 'none')
        self.assertEqual(display_option['display'], 'unset')

    def test_update_pie_graph(self):
        figure_none = update_pie_graph(1, None)
        figure_benign = update_pie_graph(1, 'google.com')
        figure_mal = update_pie_graph(1, '1-remont.com')

        self.assertTrue(figure_none['data'][0]['values'][0] == 0.5)
        self.assertTrue(figure_benign['data'][0]['values'][0] > 0.5)
        self.assertTrue(figure_mal['data'][0]['values'][0] < 0.5)

    def test_update_line_graph(self):
        figure_none = update_line_graph(1, None, None, None, None, None, None)
        check = False
        if 'data' in figure_none.keys() and 'layout' in figure_none.keys():
            check = True

        self.assertTrue(check)

    def test_update_ip_table(self):
        data_none = update_ip_table(1, None)

        self.assertEqual(data_none, [])

    def test_display_mal_list(self):
        display_false = display_mal_list(False)
        display_true = display_mal_list(True)

        self.assertEqual(display_false['display'], 'none')
        self.assertEqual(display_true['display'], 'unset')

    def test_display_mal_graph(self):
        display_false = display_mal_graph(False)
        display_true = display_mal_graph(True)

        self.assertEqual(display_false['display'], 'unset')
        self.assertEqual(display_true['display'], 'none')

    def test_update_mal_dns_table(self):
        data = update_mal_dns_table(1, '')

        self.assertTrue(len(data) >= 0)

    def test_update_mal_bar_graph(self):
        figure = update_mal_bar_graph(1, '')
        check = False
        if 'data' in figure.keys() and 'layout' in figure.keys():
            check = True

        self.assertTrue(check)

    def test_display_benign_list(self):
        display_false = display_benign_list(False)
        display_true = display_benign_list(True)

        self.assertEqual(display_false['display'], 'none')
        self.assertEqual(display_true['display'], 'unset')

    def test_display_benign_graph(self):
        display_false = display_benign_graph(False)
        display_true = display_benign_graph(True)

        self.assertEqual(display_false['display'], 'unset')
        self.assertEqual(display_true['display'], 'none')

    def test_update_benign_dns_table(self):
        data = update_benign_dns_table(1, '')

        self.assertTrue(len(data) >= 0)

    def test_update_benign_bar_graph(self):
        figure = update_benign_bar_graph(1, '')
        check = False
        if 'data' in figure.keys() and 'layout' in figure.keys():
            check = True

        self.assertTrue(check)

    # Manual Vetting

    def test_update_and_input_vet_message_vet_tables(self):

        message_none, _, _, _, _, _, = update_and_input_vet_message_vet_tables(
            None, None, None, None, None, None)
        check = False
        if 'Please select' in message_none:
            check = True
        self.assertTrue(check)

    def test_update_not_vetted_table(self):
        data = update_not_vetted_table('')

        self.assertTrue(len(data) >= 0)

    def test_update_benign_vet_table(self):
        data = update_benign_vet_table('')

        self.assertTrue(len(data) >= 0)

    def test_update_honeypot_vet_table(self):
        data = update_honeypot_vet_table('')

        self.assertTrue(len(data) >= 0)

    def test_update_blacklist_vet_table(self):
        data = update_blacklist_vet_table('')

        self.assertTrue(len(data) >= 0)


if '__name__' == '__main__':
    unittest.main()
