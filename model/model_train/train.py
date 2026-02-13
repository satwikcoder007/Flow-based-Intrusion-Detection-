import pandas as pd
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelBinarizer
from sklearn.pipeline import Pipeline
from sklearn.kernel_approximation import Nystroem
from sklearn.linear_model import RidgeClassifier
import joblib

from data_ingestion import load_all_data
from data_transformation import transform_data

df = load_all_data()
X,y = transform_data(df)

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.3, random_state=42, stratify=y
)

model = Pipeline([
    ("scaler", StandardScaler()),
    ("nystroem", Nystroem(
        kernel="rbf",
        gamma=0.75,
        n_components=1200  # controls memory
    )),
    ("classifier", RidgeClassifier(alpha=1.0))
])
model.fit(X_train, y_train)

y_pred = model.predict(X_test)
print(classification_report(y_test, y_pred))

joblib.dump(model, "model/models/model.pkl")