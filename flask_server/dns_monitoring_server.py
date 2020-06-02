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

    if (request.method == 'POST'):
        domain_json = request.get_json()
        key = list(domain_json.keys())
        domain_name = domain_json[key[0]]
        ip = domain_json[key[1]]

        input_ = np.zeros(256)
        input_[0:len(domain_json[key[0]])] = string_to_ascii(domain_json[key[0]])
        input_ = np.reshape(input_, (1, 16, 16, 1))
        send = str(model.predict(input_)[0, 0])

        try:
            csv_input = pd.read_csv('log.csv', index_col=False)
            date = domain_name + '_date'
            time = domain_name + '_time'
            ip_ = domain_name + '_ip'
            pred = domain_name + '_pred'

            print(csv_input.columns)
            if date in list(csv_input.columns):
                zeros = sum(csv_input[date] == '0')
                print(zeros)
                if zeros == 0:
                    df = pd.DataFrame({date: [datetime.now().date()], time: [datetime.now().time()], ip_: [ip], pred: [float(send)]})
                    csv_input = csv_input.append(df).fillna(0)
                else:
                    n_zeros = sum(csv_input[date] != '0')
                    csv_input[date][n_zeros] = datetime.now().date()
                    csv_input[time][n_zeros] = datetime.now().time()
                    csv_input[ip_][n_zeros] = ip
                    csv_input[pred][n_zeros] = float(send)
            else:
                row, col = csv_input.shape
                csv_input[date] = [datetime.now().date(), *('0' * (row - 1))]
                csv_input[time] = [datetime.now().time(), *('0' * (row - 1))]
                csv_input[ip_] = [ip, *np.zeros(row - 1)]
                csv_input[pred] = [float(send), *np.zeros(row - 1)]

            csv_input.to_csv('log.csv', index=False)

        except:
            csv_input = pd.DataFrame([[datetime.now().date(), datetime.now().time(), ip, float(send)]],
                                     columns=[domain_name + '_date',
                                              domain_name + '_time',
                                              domain_name + '_ip',
                                              domain_name + '_pred'
                                              ])
            csv_input.to_csv('log.csv', index=False)

        return jsonify({'p': send})


if __name__ == '__main__':
    app.run(debug=True)
