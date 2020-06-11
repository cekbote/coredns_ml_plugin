# CoreDNS Machine Learning Plugin

This CoreDNS plugin connects CoreDNS server to Machine Learning Environment for
DNS request and response analysis, monitoring and alerting. 

## Overview 

This plugin is the result of my work on a project during GSoC 2020. The goal of 
the project was introducing the integration of machine learning capabilities
into CoreDNS server functions.

The initial use case was the identification of the DNS requests for the records
of the domains that could be used by malicious hackers and other computer 
criminals. Upon the identification of the requests the plugin would either alert
of or block the requests and responses.  

## Approach

### Application Middleware

Currently, Golang doesen't have native libraries for the interaction with CUDA
at the same time, Python ecosystem have tools like TensorFlow TODO,
the plugin would intercept a request and forward it to a Python middleware for 
processing. The middleware is Python's Flask server TODO (Describe what it does)

The goal of this project is to create a CoreDNS plugin that uses machine learning to identify whether a domain name 
queried by a client is malicious or not and monitor the date as well as the time when the domain name is queried and also the IP
address of the system that queries it. 

the `mlplugin` communicates with a flask server namely: `dns_monitoring_server.py` which has a pre-trained machine learning
model that classifies whether the domain name queried is malicious or not and saves the result date, time, ip as well as
the prediction in a JSON file.

### Machine Learning

#### Learning Dataset



TODO 

#### Learning Process 

TODO

#### Data Repository 

[Elasticsearch](https://www.elastic.co/), which leads to a faster performance than loading and updating a simple Json 
file every time. The project requires `Elasticsearch 7.7.1` or higher. The Elasticsearch server has to run on the
background while storing or updating queries.  

#### Data Visualization

The results will further be analysed (TBC) using a graphing library such as [Dash.](https://plotly.com/dash/)

#### Incorporating the `mlplugin` into CoreDNS

The recommended procedure for adding external plugins can be found [here.](https://github.com/coredns/example)

However, for prototyping you can just copy the `mlplugin` directory into the `coredns/plugins` directory. 

According to the method you choose, the `plugin.cfg` and the `Corefile` would have to be changed accordingly.

#### Running the DNS Monitoring Server

For running the Flask server, a Python environment would be required to run `dns_monitoring_server.py`. This server 
runs on `127.0.0.1/5000`. 

The model that is currently being used in `dns_monitoring_server.py` can be found 
[here.](https://github.com/Chanakya-Ekbote/dns_alert_model/tree/master/saved_models) The training notebook and the 
training procedure can be found [here.](https://github.com/Chanakya-Ekbote/dns_alert_model)
