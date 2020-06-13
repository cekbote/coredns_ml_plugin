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

    if request.method == 'POST':
        domain_json = request.get_json()
        key = list(domain_json.keys())
        domain_name = domain_json[key[0]]
        ip = domain_json[key[1]]

        date_time = datetime.now()

        input_ = np.zeros(256)
        input_[0:len(domain_json[key[0]])] = string_to_ascii(domain_json[key[0]])
        input_ = np.reshape(input_, (1, 16, 16, 1))
        send = str(model.predict(input_)[0, 0])

        if ('mal' not in es.indices.get('*')) and ('benign' not in es.indices.get('*')):
            es.index(index='mal', id=1, body={})
            es.index(index='benign', id=1, body={})

        if float(send) < 0.5:
            body = es.get(index='benign', id=1)['_source']
            if domain_name in body.keys():
                body[domain_name] += 1
            else:
                body[domain_name] = 1
            update_body = {'doc': {domain_name: body[domain_name]}}
            es.update(index='benign', id=1, body=update_body)
        else:
            body = es.get(index='mal', id=1)['_source']
            if domain_name in body.keys():
                body[domain_name] += 1
            else:
                body[domain_name] = 1
            update_body = {'doc': {domain_name: body[domain_name]}}
            es.update(index='mal', id=1, body=update_body)

        if domain_name in es.indices.get('*.com'):
            body = es.get(index=domain_name, id=1)['_source']
            body['ip'].append(ip)
            body['time'].append([date_time.time().hour, date_time.time().minute, date_time.time().second])
            body['date'].append([[date_time.date().day, date_time.date().month, date_time.date().year]])
            if ip in body['count'].keys():
                body['count'][ip] += 1
            else:
                body['count'][ip] = 1
            update_body = {
                'doc': {'ip': body['ip'], 'time': body['time'], 'date': body['date'], 'count': body['count']}}
            es.update(index=domain_name, id=1, body=update_body)

        else:
            body = {'ip': [ip], 'time': [[date_time.time().hour, date_time.time().minute, date_time.time().second]],
                    'date':
                        [[date_time.date().day, date_time.date().month, date_time.date().year]], 'count': {ip: 1},
                    'status': send}
            es.index(index=domain_name, id=1, body=body)

        return jsonify({'p': send})


if __name__ == '__main__':
    app.run(debug=True)
