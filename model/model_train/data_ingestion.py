import kagglehub
from kagglehub import KaggleDatasetAdapter

import pandas as pd
import numpy as np

def load_and_clean(file_path):
    # Load dataset
    df = kagglehub.load_dataset(
        KaggleDatasetAdapter.PANDAS,
        "chethuhn/network-intrusion-dataset",
        file_path,
    )

    # Normalize column names
    df.columns = df.columns.str.strip()

    # Clean values
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)

    return df

def load_all_data():
    df_fri_portscan = load_and_clean("Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv")
    df_fri_ddos = load_and_clean("Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv")
    df_mon_benign = load_and_clean("Monday-WorkingHours.pcap_ISCX.csv")
    df_wed_dos = load_and_clean("Wednesday-workingHours.pcap_ISCX.csv")

   
    df_all = pd.concat(
        [df_fri_portscan, df_fri_ddos, df_mon_benign, df_wed_dos],
        ignore_index=True
    )

    return df_all