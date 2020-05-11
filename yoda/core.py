# AUTOGENERATED! DO NOT EDIT! File to edit: nbs/00_core.ipynb (unless otherwise specified).

__all__ = ['Data', 'Train', 'run_eval', 'run_on_dict', 'FormatTag']

# Cell
import os
import pickle
import typing
from functools import lru_cache
from io import TextIOWrapper

import blocks
import numpy as np
import pandas as pd
import sklearn
import yaml
from blocks.filesystem import GCSFileSystem
from sklearn.model_selection import cross_val_score

# Cell
class Data:
    def __init__(self, input_path: str, output_path: str, features: str, label: str, **kwargs):
        self.input_path = input_path
        self.output_path = output_path
        self.feature_list = features.split(",")
        self.label = label
        self.eval_path = kwargs.get("eval_path", None)
        self.score_path = kwargs.get("score_path", None)
        self.is_gcp = input_path.startswith("gs://")

    @property
    @lru_cache(1)
    def df(self):
        return blocks.assemble(self.input_path)

    @property
    def X(self):
        return self.df[self.feature_list]

    @property
    def y(self):
        return self.df[self.label]

    @property
    @lru_cache(1)
    def eval_df(self):
        if not self.eval_path:
            raise Exception("Please specify the eval_path")
        return blocks.assemble(self.eval_path)

    @property
    def eval_X(self):
        return self.eval_df[self.feature_list]

    @property
    def eval_y(self):
        return self.eval_df[self.label]

    @property
    @lru_cache(1)
    def score_df(self):
        if not self.score_path:
            raise Exception("Please specify the score_path")
        return blocks.assemble(self.score_path)

    @property
    def score_X(self):
        return self.score_df[self.feature_list]

    def open(self, filename) -> TextIOWrapper:
        full_path = os.path.join(self.output_path, filename)
        opener = GCSFileSystem().open if self.is_gcp else open
        with opener(full_path) as fobj:
            yield fobj

# Cell
def _import_from_string(classname: str):
    components = classname.split('.')
    mod = __import__(components[0])
    for comp in components[1:]:
        mod = getattr(mod, comp)
    return mod


class Train:
    def __init__(self, estimator: str, params: dict):
        self.estimator = _import_from_string(estimator)(**params)

    def fit(self, X: pd.DataFrame, y: pd.Series, **kwargs):
        self.estimator.fit(X, y, **kwargs)

    def predict(self, X: pd.DataFrame, **kwargs):
        self.estimator.predict(X, **kwargs)

    def save(self, fobj):
        pickle.dump(self.estimator, fobj)

# Cell
def _eval(estimator: sklearn.base.BaseEstimator = None,
          data: Data = None,
          cv=None,
          metrics: str = None) -> dict:
    if data.eval_path is not None and cv is not None:
        raise Exception(
            "eval_path: (%s) and cv: (%s) cannot co-exist" % (data.eval_path, cv))

    eval_res = dict()
    for metric in metrics:
        if data.eval_path is not None:
            estimator.fit(data.X, data.y)
            scorer = sklearn.metrics.SCORERS[metric]
            avg, sd = scorer(estimator, data.eval_X, data.eval_y), 0
        if cv is not None:
            scores = cross_val_score(
                estimator, data.X, data.y, cv=cv, scoring=metric)
            avg, sd = np.mean(scores), np.std(scores)

        eval_res[metric] = {"sd": sd, "avg": avg}
    return eval_res


def run_eval(conf_dict: dict, data: Data, estimator, output_dir: str = "eval.pkl"):
    eval_path = data.eval_path
    metrics_str = conf_dict["eval"].get("metrics")
    cv = conf_dict["eval"].get("cv")
    metrics = metrics_str.split(",") if metrics_str else None
    result = _eval(estimator, data, cv, metrics)
    conf_cp = dict(conf_dict)
    conf_cp["eval_result"] = result
    # TODO: consider to create an class here and do
    # evaluate.save()
    if output_dir:
        pickle.dump(conf_cp, data.open(output_dir))
    return result


def run_on_dict(conf_dict: dict):
    data = Data(**conf_dict['data'])
    train = Train(**conf_dict['train'])
    if "eval" in conf_dict or data.eval_path:
        run_eval(conf_dict, data, train.estimator)
    else:
        train.fit(data.X, data.y)
        train.save(data.open("model.pkl"))

# Cell
class FormatTag(yaml.YAMLObject):
    """
    This tag supporting: NOW, EPOCH, and anything from environment variable
    """
    yaml_tag = u'!format'
    yaml_loader = yaml.SafeLoader

    @classmethod
    def from_yaml(cls, loader, node):
        import calendar
        import time

        fillin_dict = dict(os.environ)
        update_dict = {
            "NOW": time.strftime("%Y%m%d_%H%M%S"),
            "EPOCH": calendar.timegm(time.gmtime()),
        }
        fillin_dict.update(update_dict)
        values = loader.construct_scalar(node)
        return values.format(**fillin_dict)