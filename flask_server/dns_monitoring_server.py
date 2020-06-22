import json

from flask import Flask, jsonify, request
import numpy as np
from elasticsearch import Elasticsearch
from datetime import datetime
import tensorflow as tf
from IPython.display import HTML, display
import tabulate
import seaborn as sns
from tensorflow.keras import layers, models, optimizers
from tensorflow.keras import backend as K
from tensorflow.keras import losses
from tensorflow.keras.utils import plot_model
from sklearn.metrics import confusion_matrix
import matplotlib.pyplot as plt
import pandas as pd
import csv

app = Flask(__name__)


def string_to_ascii(string):
    ascii_arr = np.zeros(len(string))
    for i in range(len(string)):
        ascii_arr[i] = ord(string[i])
    return ascii_arr


@app.route('/', methods=['GET', 'POST'])
def server():
    es = Elasticsearch()

    model = models.load_model(
        'C:\Chanakya\Projects\coredns_dns_ml_firewall\Code\Jupyter Notebooks\saved_models\dns_alert_model.hdf5')

    if ('mal' not in es.indices.get('*')) and \
            ('benign' not in es.indices.get('*')):
        es.index(index='mal', id=1, body={})
        es.index(index='benign', id=1, body={})

    if ('not_vetted' not in es.indices.get('*')) and \
            ('benign_vet' not in es.indices.get('*')) and \
            ('honeypot' not in es.indices.get('*')) and \
            ('blacklist' not in es.indices.get('*')):
        es.index(index='not_vetted', id=1, body={})
        es.index(index='benign_vet', id=1, body={})
        es.index(index='honeypot', id=1, body={})
        es.index(index='blacklist', id=1, body={})

    if request.method == 'POST':
        domain_json = request.get_json()
        key = list(domain_json.keys())
        domain_name = domain_json[key[0]]
        domain_name = domain_json.split('www.')
        if len(domain_name) == 1:
            domain_name = domain_name[0]
        else:
            domain_name = domain_name[1]

        ip = domain_json[key[1]]
        date_time = datetime.now()

        input_ = np.zeros(256)
        input_[0:len(domain_json[key[0]])] = string_to_ascii(domain_json[key[0]])
        input_ = np.reshape(input_, (1, 16, 16, 1))
        send = str(model.predict(input_)[0, 0])

        body_not_vetted = es.get(index='not_vetted', id=1)['_source']

        if float(send) < 0.5:
            body = es.get(index='benign', id=1)['_source']
            if domain_name in body.keys():
                body[domain_name]['count'] += 1
            else:
                body[domain_name] = {}
                body[domain_name]['count'] = 1
                body[domain_name]['status'] = \
                    float(format(((1 - float(send)) * 100), '.2f'))

                if body[domain_name]['status'] < 90:

                    body_not_vetted[domain_name] = {}
                    body_not_vetted[domain_name]['class'] = 'Benign'
                    body_not_vetted[domain_name]['acc'] = \
                        float(format(((1 - float(send)) * 100), '.2f'))

                    update_body_not_vetted = \
                        {'doc': {domain_name: body_not_vetted[domain_name]}}
                    es.update(index='not_vetted', id=1,
                              body=update_body_not_vetted)

            update_body = {'doc': {domain_name: body[domain_name]}}
            es.update(index='benign', id=1, body=update_body)

        else:
            body = es.get(index='mal', id=1)['_source']
            if domain_name in body.keys():
                body[domain_name]['count'] += 1
            else:
                body[domain_name] = {}
                body[domain_name]['count'] = 1
                body[domain_name]['status'] = \
                    float(format(float(send) * 100, '.2f'))

                if body[domain_name]['status'] < 90:

                    body_not_vetted[domain_name] = {}
                    body_not_vetted[domain_name]['class'] = 'Malicious'
                    body_not_vetted[domain_name]['acc'] = \
                        float(format(float(send) * 100, '.2f'))

                    update_body_not_vetted = \
                        {'doc': {domain_name: body_not_vetted[domain_name]}}
                    es.update(index='not_vetted', id=1,
                              body=update_body_not_vetted)

            update_body = {'doc': {domain_name: body[domain_name]}}
            es.update(index='mal', id=1, body=update_body)

        date = str(date_time.date())
        year = str(date_time.date().year)
        month = str(date_time.date().month)
        day = str(date_time.date().day)
        hour = str(date_time.time().hour)
        minutes = str(date_time.time().minute)

        if domain_name in es.indices.get('*'):
            body = es.get(index=domain_name, id=1)['_source']
            if date in body.keys():
                if hour in body[date].keys():
                    if minutes in body[date][hour].keys():
                        body[date][hour][minutes] += 1
                    else:
                        body[date][hour][minutes] = 1
                else:
                    body[date][hour] = {minutes: 1}
            else:
                body[date] = {hour: {minutes: 1}}

            if year in body.keys():
                if month in body[year].keys():
                    if day in body[year][month].keys():
                        body[year][month][day] += 1
                    else:
                        body[year][month][day] = 1
                else:
                    body[year][month] = {day: 1}
            else:
                body[year] = {month: {day: 1}}

            if ip in body['count'].keys():
                body['count'][ip] += 1
            else:
                body['count'][ip] = 1

            update_body = {
                'doc': {date: {hour: {minutes: body[date][hour][minutes]}},
                        year: {month: {day: body[year][month][day]}},
                        'count': body['count']}}
            es.update(index=domain_name, id=1, body=update_body)

        else:
            body = {date: {hour: {minutes: 1}}, year: {month: {day: 1}},
                    'count': {ip: 1}, 'status': send}
            es.index(index=domain_name, id=1, body=body)

        return jsonify({'p': send})


if __name__ == '__main__':
    app.run(debug=True)
