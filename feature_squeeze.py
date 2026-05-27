import json
import numpy as np
import tensorflow as tf
from data_loader import TrainDataLoader, TestDataLoader
from hyperparams import Hyperparams as H
from paths import Paths as P
from model import transformer_model
from attack import ATTACKS
from evaluate import evaluate


def _estimate_static_importance(loader):
    pos = np.zeros(H.static_feature_len, dtype=np.float64)
    neg = np.zeros(H.static_feature_len, dtype=np.float64)
    n_pos = 0
    n_neg = 0
    for idx in range(len(loader)):
        (_, static), labels = loader[idx]
        labels = labels.reshape(-1)
        pos += static[labels == 1].sum(axis=0)
        neg += static[labels == 0].sum(axis=0)
        n_pos += int((labels == 1).sum())
        n_neg += int((labels == 0).sum())
    p_pos = pos / max(n_pos, 1)
    p_neg = neg / max(n_neg, 1)
    return np.abs(p_pos - p_neg)


def select_top_k_mask(loader, k):
    importance = _estimate_static_importance(loader)
    keep_idx = np.argsort(importance)[-k:]
    mask = np.zeros(H.static_feature_len, dtype=np.float32)
    mask[keep_idx] = 1.0
    return mask


class _SqueezedLoader:
    def __init__(self, base_loader, mask):
        self.base = base_loader
        self.mask = mask

    def __len__(self):
        return len(self.base)

    def __getitem__(self, idx):
        sample_batch, labels = self.base[idx]
        tokens, static = sample_batch
        return (tokens, (static * self.mask).astype(np.int32)), labels


def _squeezed_attack_fn(base_attack, mask):
    def fn(bundle, sample_batch, labels):
        tokens, static = sample_batch
        squeezed = (tokens, (static * mask).astype(np.int32))
        adv = base_attack(bundle, squeezed, labels)
        if isinstance(adv, dict) and "embedded" in adv:
            adv["static"] = (adv["static"] * mask).astype(np.int32)
            return adv
        adv_tokens, adv_static = adv
        return [adv_tokens, (adv_static * mask).astype(np.int32)]
    return fn


if __name__ == "__main__":
    bundle = transformer_model().get_models()
    bundle["model"].load_weights(P.saved_model)
    train_loader = TrainDataLoader()
    mask = select_top_k_mask(train_loader, k=max(int(0.1 * H.static_feature_len), 1))
    test_loader = TestDataLoader()
    squeezed_test = _SqueezedLoader(test_loader, mask)
    results = {}
    for name, fn in ATTACKS.items():
        results[name] = evaluate(bundle, squeezed_test, attack_fn=_squeezed_attack_fn(fn, mask))
    with open("results_squeeze.json", "w") as f:
        json.dump(results, f, indent=2)
    print(json.dumps(results, indent=2))
