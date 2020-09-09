import csv
import sys
import logging
import wmi
import subprocess
import pandas as pd
from password_strength import PasswordStats


# Note: Please make sure windows logging is initiated, follow the fink below in case it's not
# https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-firewall/configure-the-windows-firewall-log

# This is the location where firewall logs are saved
FIREWALL_LOG_PATH = "C:\\Windows\\System32\\LogFiles\\Firewall\\pfirewall.log"

# the list below contains the threshold values, by which we
# either assign the metric a label of "true" or "false"
BOOL_LIST = [4, 2000, 8000, True, True, True, True,
             'y', True, 0.01, 0.01, 0.01, 0.01, 'y',
             'y', 'y', 'y', True]


def read_firewall_logs():
    """
    This a helper file that read the firewall log
    and preprocesses it for metric extraction
    :return: dataframe with cleaned firewall log
    """

    df = pd.read_csv(FIREWALL_LOG_PATH).astype(str)
    col_names = df.iloc[2].str.split(' ').tolist()
    new_col_names = col_names[0][1:]
    def row_split(row):
        return row.str.split(' ')
    df_new = df.iloc[4:].apply(row_split, axis=1)
    df_new_spit = pd.DataFrame(df_new[df_new.columns.tolist()[0]].to_list(), columns=new_col_names)
    df_new_spit["datetime"] = df_new_spit["date"] + " " + df_new_spit["time"]
    df_new_spit["datetime"] = pd.to_datetime(df_new_spit["datetime"], format="%Y-%m-%d %H:%M:%S")
    return df_new_spit


def pkt_rate(df):
    """
    computes the packets rate/sec
    :param df: firewall log dataframe
    :return: packets rate/sec
    """

    time_diff = (df["datetime"].max() - df["datetime"].min()).seconds
    return df.shape[0]/time_diff


def gen_firewall_log_metrics():
    """
    This function creates all the metrics associated with
    the firewall log sub-component of the firewall security
    component
    :return: dictionary with the firewall log metric values
    """

    print("generating firewall log metrics ---------> please wait")
    try:
        df = read_firewall_logs()
        adr = df.loc[df["action"]=="ALLOW"].shape[0]/df.loc[df["action"]=="DROP"].shape[0]
        icmp_rate = pkt_rate(df.loc[df["protocol"]=="ICMP"])
        tcp_rate = pkt_rate(df.loc[df["protocol"] == "TCP"])
    except FileNotFoundError:
        logging.warning("Firewall logging not initiate; please initiate it using the link below \n "
              "https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-firewall/configure-the-windows-firewall-log \n"
                        "Assuming default values of adr=6, icmp_rate = 9000, tcp_rate=3000")
        adr, icmp_rate, tcp_rate = 6, 9000, 3000

    except:
        logging.warning("Firewall logs seem to be empty \n "
                        "Assuming default values of adr=6, icmp_rate = 9000, tcp_rate=3000")
        adr, icmp_rate, tcp_rate = 6, 9000, 3000

    return {"adr":adr, "icmp_rate":icmp_rate, "tcp_rate":tcp_rate}


def gen_firewall_setting_metrics():
    """
    This function generates the firewall setting values
    of a particular windows os, using netsh commands, which
    is called with the help of subprocess function
    :return: dictionary of firewall setting metrics
    """

    cmd = ['global', 'domainprofile', 'publicprofile', 'privateprofile']
    metric_index = [4, 3, 3, 3]
    bool_cond = ['0:Disabled', 'ON', 'ON', 'ON']
    setting_dict = {}
    for i, setting in enumerate(cmd):
        output = subprocess.check_output(f'netsh advfirewall show {setting}')
        new_line = output.splitlines()
        metric_val = new_line[metric_index[i]].decode("utf-8").split()
        if i == 0:
            setting_dict["IPSecProfile"] = metric_val[1] != bool_cond[i]
        else:
            setting_dict[setting] = metric_val[1] == bool_cond[i]
    print("Please input a firewall settings:")
    print("is there a firewall rule to block mshta.exe, Cscript.ext, Wscript.rxt (y/n): ")
    rule = input()
    print("Data is being processed, please wait for the next prompt: ")
    setting_dict["firewall_rule"] = rule
    if all([setting_dict["domainprofile"], setting_dict["publicprofile"], setting_dict["privateprofile"]]):
        setting_dict["all_profiles"] = True
    else:
        setting_dict["all_profiles"] = False

    return setting_dict


def event_parser(event=None):
    """
    This is helper function, that queries the event logs
    and finds the count of specific eventIDs
    :param event: event ID under consideration
    :return: count of these events
    """

    q_object = wmi.WMI('.')
    if event is not None:
        query = ("SELECT * FROM Win32_NTLogEvent WHERE EventCode = {}".format(event))
    else:
        query = ("SELECT * FROM Win32_NTLogEvent")
    query_op = q_object.query(query)
    return len(query_op)


def gen_event_log_metrics():
    """
    This function parses through the windows events logs
    and finds the normalized count i.e. % of specific
    events as metrics
    :return: dictionary containing the application security
             metrics
    """

    print("Generating event log metrics -------> please wait")
    sum_total = event_parser()
    event_dict = {"event_set_1":[5165, 5158, 5154],
                  "event_set_2":[4625],
                  "event_set_3":[6006],
                  "event_set_4":[7034]
                  }
    event_metrics = {}
    for key, vals in event_dict.items():
        event_metrics[key] = 0
        for val in vals:
            event_metrics[key] += event_parser(val)/sum_total
    return event_metrics


def gen_browser_setting():
    """
    This function requests the user for browser
    security practices it follows, as these values
    are case sensitive, one has to be precise in
    it's inputs
    :return: dictionary containing the browser security
            metrics
    """

    print("Please input your browser settings")
    print("is the browser auto-update enabled (y/n): ")
    bap = input()
    print("are all unwanted plugins disabled (y/n): ")
    upd = input()
    print("are pop-ups blocked (y/n): ")
    pub = input()
    print("is phishing and malware protection enabled (y/n): ")
    pmpe = input()
    browser_dict = {"bap": bap, "upd":upd, "pub":pub, "pmpe":pmpe}
    # print(browser_dict)

    return browser_dict


def gen_password_strength():
    """
    This function request the user for his password
    and calculates the strength and the flag of the
    password strength with help of password_strength
    library
    :return:
    """

    print("Please type in your password (to assess it's strength")
    password = input()
    stats = PasswordStats(password)
    print(f"your password strength is: {stats.strength()}")
    return {"password_strength": stats.strength()>=0.6}


def stats_collector():
    """
    This function aggregates all the raw metric values
    and processes it based on the corresponding thresholds
    to generate labels which will be later used for the
    :return: a final dictionary containing all the metric labels
    """

    firewall_logs = gen_firewall_log_metrics()
    firewall_setting = gen_firewall_setting_metrics()
    event_logs = gen_event_log_metrics()
    browser_setting = gen_browser_setting()
    pass_strength = gen_password_strength()
    updated_dict = {}
    for diction in [firewall_logs, firewall_setting, event_logs, browser_setting, pass_strength]:
        updated_dict.update(diction)

    final_metrics_dict, i = {}, 0

    for key, vals in updated_dict.items():
        if key in ["adr", "icmp_rate", "tcp_rate", "event_set_1",
                   "event_set_2", "event_set_3", "event_set_4" ]:
            if vals >= BOOL_LIST[i]:
                final_metrics_dict[key] = "false"
            else:
                final_metrics_dict[key] = "true"
        else:
            if vals == BOOL_LIST[i]:
                final_metrics_dict[key] = "true"
            else:
                final_metrics_dict[key] = "false"
        i += 1
    print(final_metrics_dict)
    return final_metrics_dict
