import json
import os
import shutil
import sys
import tempfile

import numpy as np

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, REPO)


def _layout(root, n=4):
    sub = os.path.join(root, "NEW")
    for kind in ("Benign", "Malicious"):
        os.makedirs(os.path.join(sub, kind, "exe"), exist_ok=True)
        os.makedirs(os.path.join(sub, kind + "_Disassembled", "exe"), exist_ok=True)
        os.makedirs(os.path.join(sub, kind + "_Tokenized", "exe"), exist_ok=True)
    for i in range(n):
        for kind in ("Benign", "Malicious"):
            name = "{}_{}".format(kind.lower(), i)
            tok = os.path.join(sub, kind + "_Tokenized", "exe", name)
            with open(tok, "w") as f:
                f.write("\n".join("1 2 3" for _ in range(8)))
            exe = os.path.join(sub, kind, "exe", name)
            with open(exe, "wb") as f:
                f.write(b"MZ" + b"\x00" * 62)


def test_pipeline_smoke():
    root = tempfile.mkdtemp(prefix="malsmoke_")
    try:
        _layout(root, n=4)
        os.environ["MALWARE_DATASET_ROOT"] = root

        for mod in ("paths", "hyperparams", "data_loader", "model", "evaluate", "attack"):
            sys.modules.pop(mod, None)

        from hyperparams import Hyperparams as H
        H.batch_size = 2
        H.executable_size = 8
        H.num_epochs = 1
        H.attack_budget = 2
        H.val_test_ratio = 0.5
        H.test_ratio_in_val_test = 0.5

        from model import transformer_model
        from data_loader import TrainDataLoader, TestDataLoader
        from evaluate import evaluate
        from attack import ATTACKS

        bundle = transformer_model().get_models()
        import tensorflow as tf
        bundle["model"].compile(
            optimizer=tf.keras.optimizers.Adam(learning_rate=1e-4),
            loss=tf.keras.losses.BinaryCrossentropy(),
            metrics=["accuracy"],
        )
        train_loader = TrainDataLoader()
        test_loader = TestDataLoader()
        assert len(train_loader) > 0
        assert len(test_loader) > 0
        bundle["model"].fit(train_loader, epochs=1, verbose=0)

        for name, fn in ATTACKS.items():
            results = evaluate(bundle, test_loader, attack_fn=fn)
            assert 0.0 <= results["clean_accuracy"] <= 1.0, name
            assert 0.0 <= results["robust_accuracy"] <= 1.0, name
            assert 0.0 <= results["attack_success_rate"] <= 1.0, name
    finally:
        shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    test_pipeline_smoke()
    print("OK")
