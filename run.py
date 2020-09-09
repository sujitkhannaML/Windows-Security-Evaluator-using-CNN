import pandas as pd
import numpy as np
from keras.models import load_model
from read_logs import stats_collector

SAVED_MODEL = 'trained_cnn.h5'


def get_metrics():
    """
    This function generates the system metrics
    required for the evaluation of the windows
    operating system security
    :return: numpy array for the model prediction
    """

    metrics_dict = stats_collector()
    df = pd.DataFrame(metrics_dict, index=[1])
    df = df.replace("false", 0)
    df = df.replace("true", 1)
    df["dummy"] = 1
    df = df.drop(columns=['domainprofile', 'publicprofile', 'privateprofile'])
    ip_set = np.reshape(df.values, (df.shape[0], 4, 4))
    return ip_set


def get_security_score():
    """
    This function extracts the numpy input array,
    and feeds it to the saved/trained ML model at
    location SAVED_MODEL global variable, and prints
    the overall security score
    :return:
    """

    input_set = get_metrics()
    x_test = np.expand_dims(input_set, -1)
    model = load_model(SAVED_MODEL)
    pred = model.predict(x_test)
    print(f"Overall Security Score is {np.argmax(pred)}")



get_security_score()





