import pandas as pd

LABEL_MAP = {
    "BENIGN": "NORMAL",

    # Wednesday
    "DoS Hulk": "DOS_HULK",
    "DoS GoldenEye": "DOS_GOLDENEYE",
    "DoS slowloris": "DOS_SLOWLORIS",
    "DoS Slowhttptest": "DOS_SLOWHTTPTEST",

    # Friday
    "PortScan": "RECON",
    "DDoS": "DOS_DDOS"
}

FEATURE_COLUMNS = [
    "Average Packet Size",
    "Packet Length Std",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Init_Win_bytes_forward",
    "Avg Bwd Segment Size",
    "Flow Duration",
    "Destination Port"
]

def relabel(df):
    # Keep only required labels
    df = df[df["Label"].isin(LABEL_MAP.keys())].copy()

    # Relabel
    df.loc[:, "Label"] = df["Label"].map(LABEL_MAP)

    # Select features
    df = df[FEATURE_COLUMNS + ["Label"]].copy()

    return df

def balance_dataset(df):
    MAX_SAMPLES_PER_CLASS = 10000  # adjust if RAM allows
    return (
        df
        .groupby("Label", group_keys=False)
        .apply(lambda x: x.sample(
            n=min(len(x), MAX_SAMPLES_PER_CLASS),
            random_state=42))
        .sample(frac=1, random_state=42)  # shuffle
    )

def transform_data(df):
    df = relabel(df)
    df = balance_dataset(df)
    X = df[FEATURE_COLUMNS]
    y = df["Label"]

    return X,y

