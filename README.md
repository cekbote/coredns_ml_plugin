# CoreDNS Machine Learning Plugin 

[![License](https://img.shields.io/github/license/cekbote/coredns_ml_plugin?style=flat-square)](https://github.com/cekbote/coredns_ml_plugin/blob/master/LICENSE)
[![GitHub forks](https://img.shields.io/github/forks/cekbote/coredns_ml_plugin?style=flat-square)](https://github.com/cekbote/coredns_ml_plugin/network)

This repository contains code for connecting the CoreDNS server to a Machine 
Learning Environment for DNS request and response analysis, monitoring and 
alerting.

## Overview 

This repository is the result of my work on a project during GSoC 2020. The goal 
of the project was introducing the integration of machine learning capabilities
with the CoreDNS server.

The initial use case was the identification of the DNS requests ,via machine 
learning, for the records of the domains that could be used by malicious hackers 
and other computer criminals. Upon the identification of the requests the plugin 
would either alert the sysadmin for manual vetting or block the requests and 
responses.  

## Approach

### General Overview

Currently, Golang doesn't have native libraries for the interaction with the 
CUDA platform. At the same time, the Python ecosystem has tools like TensorFlow,
PyTorch, MXNet and various others that not only interact with the CUDA platform
but also allows for the easy prototyping and evaluation of deep learning models. 

This project combines the deep learning capabilities that the Python ecosystem
provides, with CoreDNS, by creating:
 - A CoreDNS Plugin (ML Plugin): The plugin intercepts requests and forwards 
them to the Python middleware for further processing. 
 - An Application Middleware (Flask Server): The middleware is a Python Flask 
Server that receives the request along with other metadata. The Flask Server 
infers whether the request was malicious or benign, via a pre-trained TensorFlow 
Model, and then sends back a response based on this result, to the plugin. It 
also stores the result along with other metadata, to a database.
- A Visualization Dashboard (Dash Application): To visualize and analyse the 
results, a visualization dashboard (Dash Application) was created. This
application can also be used to manually vet domain names. 

![image info](./readme_assets/general_overview.png)

### Machine Learning

__Learning Dataset__

The deep-learning model is trained on a COVID-19 Cyber Threat Coalition 
Blacklist for malicious domains that can be found 
[here](https://blacklist.cyberthreatcoalition.org/vetted/domain.txt) and on a 
list of benign domains from DomCop that can be found 
[here](https://www.domcop.com/top-10-million-domains). 

Currently, the pre-trained model has been trained on the top 500 domain names 
from both these datasets. The final version of the pre-trained model will be 
trained on the entirety of both the datasets.  

__Learning Process__

Data Preprocessing: Each domain name is converted into a unicode code point 
representation and then extended to a numpy array of a length 256. The dataset 
was created by combining the malicious domains as well as the non-malicious. 
The dataset was split as follows:
- Train Set: 80% of the dataset.
- Validation Set: 10 % of the dataset
- Test Set: 10% of the dataset

Training: The deep-learning model is a Convolutional Neural Net that is 
trained using batch gradient descent with the Adam optimizer.

## Inner Working of the Application

![image info](./readme_assets/pipeline_explained.png)

### Machine Learning Plugin

The machine learning plugin forwards a request to the Flask Server for domain
name analysis. The Flask Server then processes the request and sends back
whether the domain name is malicious or benign. If the domain name is malicious,
the plugin prevents the fallthrough to other plugins and sends back a Honeypot 
or Blackhole IP.

### Flask Server

The Flask Server first preprocessess the request forwarded from the 
Machine Learning Plugin. The preprocesssed request is then sent to the machine 
learning model where it infers whether it is benign or malicious.

If the model is highly confident that the domain name is benign, a response is
sent back to the Machine Learning Plugin that allows the fallthrough to other
plugins. 

If the model is highly confident that the domain name is malicious, a response 
is sent back to the Machine Learning Plugin that prevents the fallthrough to 
other plugins. Moreover, the Machine Learning Plugin sends back a Honeypot or a
Blackhole IP to the user querying the malicious domain.

If the model is not very confident about the its inference, then the the
manually vetted lists are looked at. If the domain name exists in the benign
domain list, then the same procedure is followed as described above for benign 
domains. Similarly, if a malicious domain exists in the malicious domain list,
then the same procedure is followed as described above for malicious domains.
If the domain name is not present in any of the lists, then the same procedure 
is followed as described above for benign domains, however, these domains are 
stored in the database for manual vetting.

In all the three above scenarios, the results as well as other metadata are 
stored in the database.

### Dash Application

The Dash Application has two main use cases:

- Historical Analysis: The application allows the user to historically analyse
the frequency at which domains have been queried and the IP addresses of the 
users querying those domains. Moreover, it also allows the user to investigate 
the domains that the model is confident about, in order to vet false positives
and false negatives. 
- Manual Vetting: The application allows a user to manually vet domain names
that the model is not confident about. It then stores these manually vetted
lists in the database. 

## Implementation

### Machine Learning Plugin and CoreDNS Build

The machine learning plugin is a CoreDNS plugin that forwards requests to the 
Flask Server via HTTP POST requests. Once the Flask server processes the request,
it sends the prediction, whether the domain name is malicious or benign, back to 
the plugin. Depending on the nature of the domain name, the plugin can be 
configured to allow the request to fall through to the other plugins or send the
request to a honeypot or a blackhole.

To install and start CoreDNS please take a look at the CoreDNS 
[repository](https://github.com/coredns/coredns). To add external plugins, 
please take a look at the [example plugin](https://github.com/coredns/example).

To add the plugin to a particular port say 1053, please make the changes to the
Corefile as shown below:

```
.:1053 {
    mlplugin
}
```

---

### Application Middleware with Flask

The middleware is a Python Flask Server that contains the pre-trained 
Convolutional Neural Network. The Flask Server receives the domain name queried 
as well as the IP address of the machine used to query that particular domain 
name, as a JSON message, via HTTP POST requests from the plugin.  

Once the Flask Server receives the domain name and the IP address, the domain 
name is preprocessed and then passed to the pre-trained deep learning model. The
deep learning model then classifies whether the domain name is of a malicious 
website or not and then sends the same back to plugin as a JSON message.

The classification result as well as other metadata such as the IP address, the 
date and time of the request are stored in a NoSQL database, namely 
Elasticsearch, due to which storing and querying the classification result and 
the metadata is a fast process. 

Before running the Flask Server, it is recommended that the Elasticsearch server
is running in the background. To install Elasticsearch, please follow the 
instructions found on this 
[page](https://phoenixnap.com/kb/install-elasticsearch-ubuntu). Once 
Elasticsearch is installed, `cd` into it and enter `bin/elasticsearch` to run the 
Elasticsearch server. 
 
To run the Flask Server, `cd` into the `flask_server` directory and then enter
`python dns_monitoring_server.py` in the command line. 

---

### TensorFlow Model

#### Tensorflow Model Definition

The pre-trained deep learning model is a Convolutional Neural Net whose input is
a (16, 16, 1) shaped array and the output is a single value lying in between 0 
and 1. If the output value is less than 0.5 the domain name is considered benign
, else it is considered malicious. 

The model summary can be found below:


| Layer      | Output Shape          | Activation   | Number of Parameters |
|:----------:|:---------------------:|:------------:|:--------------------:|
| Input      | (None, 16, 16, 1 )    | -            |0                     |
| Conv2D     | (None, 15, 15, 16)    | Relu         |80                    |
| MaxPooling | (None, 7, 7, 16)      | -            |0                     |
| Conv2D     | (None, 6, 6, 16)      | Relu         |1040                  |
| MaxPooling | (None, 3, 3, 16)      | -            |0                     |
| Conv2D     | (None, 2, 2, 8 )      | Relu         |520                   |
| Flatten    | (None, 32)            | -            |0                     |
| Dense      | (None, 8 )            | Relu         |264                   |
| Dense      | (None, 1 )            | Sigmoid      |9                     |

#### TensorFlow Model Visualization

The model can be visualized as follows: 

![image info](./readme_assets/model_.png)

#### Results

The accuracy for the Train Set, Validation Set and Test Set is as follows:

| Metric   | Train Set   | Validation Set | Test Set |  
|----------|-------------|----------------|----------|
| Accuracy | 99.25 %     | 98.00 %        | 98.00 %  |

The model training procedure as well as the pre-trained model can be found in 
the `tensorflow_model` directory. 

---

### Visualization Dashboard

To analyse and visualize the results stored in the in the Elasticsearch 
database, a Dash Application was created. There are two main components to the 
Visualization Dashboard :
- Historical analysis: The application allows the user to historically analyse
the frequency at which domains have been queried and the IP addresses of the 
users querying those domains
- Manual Vetting: The application allows a user to manually vet domain names
that the model is not confident about

#### Historical Analysis

A demo of the application can be seen below:

<p align = "center">
    <img style="float: right;" src="https://github.com/chanakyaekbote/coredns_ml_plugin/blob/master/readme_assets/dash_app_gif.gif">
</p>

Historical Analysis has three main use cases:

- Domain Name Analysis: The application allows the user to search for a
a particular domain name along with a request time range. The application will 
then search for that particular domain name in the Elasticsearch database. Once the 
domain name is found, the app will display the number of requests to that 
particular domain name in that time range, the nature of the domain name 
(benign or malicious) and also the IP addresses that have queried that 
particular domain name. This allows for a domain specific analysis.


<p align = "center">
  <img src="https://github.com/chanakyaekbote/coredns_ml_plugin/blob/master/readme_assets/domain_name_app_1.PNG" 
  width="700"/> 
</p>

- Analysis of Malicious Domain Names: The application allows the user to
visualize the top 20 malicious domains queried, as a bar graph. It also displays 
a list of all the malicious domains queried which can be seen via a toggle
switch in the same window. This allows the user to gain a general picture of all
the malicious domain names queried and also helps in identifying model 
misclassification.

<p float="left" align = "center">
  <img src="https://github.com/chanakyaekbote/coredns_ml_plugin/blob/master/readme_assets/malicious_app_1.PNG" 
  width="400"/>
  <img src="https://github.com/chanakyaekbote/coredns_ml_plugin/blob/master/readme_assets/malicious_app_2.PNG" 
  width="400"/>
</p>

- Analysis of Benign Domain Names: The application allows the user to
visualize the top 20 benign domains queried, as a bar graph. It also displays 
a list of all the benign domains queried which can be seen via a toggle
switch in the same window. This allows the user to gain a general picture of all
the benign domain names queried and also helps in identifying model 
misclassification.

<p float="left" align = "center">
  <img src="https://github.com/chanakyaekbote/coredns_ml_plugin/blob/master/readme_assets/benign_app_1.PNG" width
  ="400"/>
  <img src="https://github.com/chanakyaekbote/coredns_ml_plugin/blob/master/readme_assets/benign_app_2.PNG" width
  ="400"/>
</p>

#### Manual Vetting

A demo of the application can be seen below:

<p align = "center">
    <img style="float: right;" src="https://github.com/cekbote/coredns_ml_plugin/blob/master/readme_assets/manual_vetting.gif">
</p>

Manual Vetting allows the user to manually vet domain names that the model has 
a low confidence on, thereby creating a new dataset of malicious or benign 
domains. This dataset can be used for blocking or allowing domains and also for 
updating the dataset for retraining the model. 

<p align = "center">
  <img src="https://github.com/cekbote/coredns_ml_plugin/blob/master/readme_assets/manual_vetting_screenshot.PNG" 
  width="700"/> 
</p>

To run the Dash application `cd` into the `analysis_app` directory and then
enter`python malicious_domain_name_analysis.py` in the command line. Please note
that the Elasticsearch server has to run in the background.

___

### Testing Harness

As there are various components to the machine learning pipeline, each component
has its own testing harness. 

#### CoreDNS Test Harness

To test whether CoreDNS works properly, make the following change to the 
Corefile:

```
.:1053 {
    whoami
}
```

Then 'cd' into the `coredns` directory and enter `./coredns` in the command line.

Open a new terminal and then enter `dig @127.0.0.1 -p 1053 www.example.com`. If a 
reply is received CoreDNS is working properly.

#### Elasticsearch Test Harness

To test whether Elasticsearch works properly, first run Elasticsearch by going 
into the Elasticsearch directory and then enter `bin/elasticsearch` in the 
command line. Next enter the following into a new terminal:

```
python
>>> from elasticsearch import Elasticsearch
>>> es = Elasticsearch()
>>> es.indices.get('*')
``` 

If Python doesn't throw any errors and returns a JSON object, Elasticsearch is 
working well.

#### Machine Learning Plugin and Flask Server Test Harness

To test whether the machine learning plugin as well as the Flask server works 
properly first run CoreDNS with the machine learning plugin at a particular 
port, run Elasticsearch and run the Flask Server.

Next open a new terminal and enter `dig @127.0.0.1 - p port_number 
www.google.com`. Then open the terminal where the CoreDNS server is running and
check the output. If the output contains either `Benign Domain: [domain_name] |
Probability: [probability_value]` or `Malicous Domain: [domain_name] | 
Probability: [probability_value]` then both the machine learning plugin and the
Flask server are working well. 

#### Dash Application Test Harness

The Dash application has an in built debugger that throws errors if anything
goes wrong. If there are no errors thrown by the debugger, the application is 
working well.




  
