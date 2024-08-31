import re
import json
import joblib
import os
import numpy as np
import statistics

from sklearn.pipeline import make_pipeline
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.tree import DecisionTreeClassifier
from sklearn.multioutput import MultiOutputClassifier
from sklearn import __version__ as sklearn_version
from typing import List, Tuple
from pathlib import Path

models_path = os.path.join("cli_vuln", "models")
max_length = 10


def train_create_model(ds) -> tuple:
    ds = ds.dropna()
    train_x, test_x, train_y, test_y = train_test_split(ds["code"], ds[["safety", "type"]], test_size=0.3, random_state=42)

    model = make_pipeline(TfidfVectorizer(), MultiOutputClassifier(DecisionTreeClassifier(random_state=42)))
    model.fit(train_x, train_y)

    pred = model.predict(test_x)

    accuracy_safety = accuracy_score(test_y["safety"], pred[:, 0])
    accuracy_type = accuracy_score(test_y["type"], pred[:, 1])

    report_safety = classification_report(test_y["safety"], pred[:, 0])
    report_type = classification_report(test_y["type"], pred[:, 1])

    return model, accuracy_safety, accuracy_type, report_safety, report_type


def _combine_predictions(models, data) -> Tuple[str, str]:
    predictions = [model.predict([f"{data}"])[0] for model in models]

    predictions = np.array(predictions)
    predictions_safety = predictions[:, 0]
    predictions_type = predictions[:, 1]

    most_frequent_safety = statistics.mode(predictions_safety)
    most_frequent_type = statistics.mode(predictions_type)

    return most_frequent_safety, most_frequent_type


def compile_models(code: str) -> Tuple[str, str]:
    models = [joblib.load(f"cli_vuln/models/{model}") for model in get_models()]

    return _combine_predictions(models, code)


def scan(path: Path) -> List[Tuple[str, str]]:
    output = []

    if path.is_dir():
        for _path in path.glob("**/*.php"):
            if _path.is_dir():
                continue

            with open(_path, "r", encoding="iso-8859-1") as arquivo_php:
                predictions = compile_models(arquivo_php.read())
                output.append(predictions)

    if path.is_file() and path.suffix.lower() == ".php":
        with open(path, "r", encoding="iso-8859-1") as arquivo_php:
            compile_models(arquivo_php.read())

        predictions = compile_models(path)
        output.append(predictions)

    return output


def get_models():
    models = os.listdir(models_path)

    return models


def mode_predictions(predictions: List[Tuple[str, str]]):
    if len(predictions) == 0:
        return None, None

    predictions = np.array(predictions)
    predictions = predictions.reshape(-1, 2)

    predictions_safety = predictions[:, 0]
    predictions_type = predictions[:, 1]

    most_frequent_safety = statistics.mode(predictions_safety)
    most_frequent_type = statistics.mode(predictions_type)

    return most_frequent_safety, most_frequent_type


def remove_model(model_number: int):
    models = get_models()
    model_name = models[model_number - 1]
    os.remove(os.path.join(models_path, model_name))
