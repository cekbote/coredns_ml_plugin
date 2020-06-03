import json

from flask import Flask, jsonify, request
import numpy as np
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

        try:
            with open('log.json') as json_file:
                data = json.load(json_file)

            if domain_name in list(data.keys()):
                data[domain_name]['date'].append([date_time.date().day, date_time.date().month, date_time.date().year])
                data[domain_name]['time'].append(
                    [date_time.time().hour, date_time.time().minute, date_time.time().second])
                data[domain_name]['ip'].append(ip)
                data[domain_name]['prediction'].append(float(send))
            else:
                data[domain_name] = {'date': [date_time.date().day, date_time.date().month, date_time.date().year],
                                     'time': [[date_time.time().hour, date_time.time().minute, date_time.time().second]],
                                     'ip': [ip], 'prediction': [float(send)]}

            with open('log.json', 'w') as json_file:
                json.dump(data, json_file, sort_keys=True)

        except:
            data = {domain_name: {'date': [[date_time.date().day, date_time.date().month, date_time.date().year]],
                                  'time': [[date_time.time().hour, date_time.time().minute, date_time.time().second]],
                                  'ip': [ip], 'prediction': [float(send)]}}
            with open('log.json', 'w') as json_file:
                json.dump(data, json_file, sort_keys=True)

        return jsonify({'p': send})


if __name__ == '__main__':
    app.run(debug=True)
