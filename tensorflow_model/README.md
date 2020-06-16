# DNS Alert Model

This directory contains the the code for the training and evaluation of a binary 
classifier for alerting whether a person is querying a malicious domain.

The `notebooks` directory contains the Jupyter Notebook where the training 
procedure can be observed. The `saved_models` directory contains the model that 
has achieved the maximum validation accuracy while training.

## Training

The deep-learning model is trained on a COVID-19 Cyber Threat Coalition 
Blacklist for malicious domains that can be found 
[here](https://blacklist.cyberthreatcoalition.org/vetted/domain.txt) and on a 
list of benign domains from DomCop that can be found 
[here](https://www.domcop.com/top-10-million-domains). 

Currently, the pre-trained model has been trained on the top 500 domain names 
from both these datasets. The final version of the pre-trained model will be 
trained on the entirety of both the datasets.

The dataset was created by combining the malicious domains as well as the benign
domains. The dataset was split as follows: 
- Train Set: 80% of the dataset.
- Validation Set: 10 % of the dataset
- Test Set: 10% of the dataset

## Accuracy 

The accuracy for the Train Set, Validation Set and Test Set is as follows:

| Metric   | Train Set   | Validation Set | Test Set |  
|----------|-------------|----------------|----------|
| Accuracy | 99.25 %     | 98.00 %        | 98.00 %  |

The training graphs, confusion matrices and other metrics can be found in the 
`training_dns_alert_model.ipynb` notebook in the `notebooks` directory.
