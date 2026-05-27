import json
import numpy as np


def _bundle_and_model(model_or_bundle):
    if isinstance(model_or_bundle, dict):
        return model_or_bundle, model_or_bundle["model"]
    return {"model": model_or_bundle}, model_or_bundle


def _predict_clean(model, sample_batch):
    probs = model.predict(sample_batch, verbose=0).reshape(-1)
    return (probs >= 0.5).astype(np.int32)


def _predict_adv(bundle, adv):
    if isinstance(adv, dict) and "embedded" in adv:
        encode_model = bundle["encode_model"]
        probs = encode_model.predict(
            [adv["embedded"], adv["mask"], adv["static"].astype(np.float32)],
            verbose=0,
        ).reshape(-1)
    else:
        probs = bundle["model"].predict(adv, verbose=0).reshape(-1)
    return (probs >= 0.5).astype(np.int32)


def evaluate(model_or_bundle, loader, attack_fn=None, out_path=None):
    bundle, model = _bundle_and_model(model_or_bundle)
    n_total = 0
    n_correct = 0
    n_robust_correct = 0
    n_mal_correct = 0
    n_mal_evaded = 0
    for idx in range(len(loader)):
        sample_batch, labels = loader[idx]
        clean_pred = _predict_clean(model, sample_batch)
        labels = labels.reshape(-1)

        n_total += len(labels)
        n_correct += int((clean_pred == labels).sum())

        is_mal_correct = (labels == 1) & (clean_pred == 1)
        n_mal_correct += int(is_mal_correct.sum())

        if attack_fn is not None:
            adv = attack_fn(bundle, sample_batch, labels)
            adv_pred = _predict_adv(bundle, adv)
            n_robust_correct += int((adv_pred == labels).sum())
            n_mal_evaded += int(((adv_pred == 0) & is_mal_correct).sum())

    clean_acc = n_correct / max(n_total, 1)
    results = {"n_total": n_total, "clean_accuracy": clean_acc}
    if attack_fn is not None:
        results["robust_accuracy"] = n_robust_correct / max(n_total, 1)
        results["attack_success_rate"] = n_mal_evaded / max(n_mal_correct, 1)
        results["n_mal_originally_correct"] = n_mal_correct
        results["n_mal_evaded"] = n_mal_evaded
    if out_path is not None:
        with open(out_path, "w") as f:
            json.dump(results, f, indent=2)
    return results
