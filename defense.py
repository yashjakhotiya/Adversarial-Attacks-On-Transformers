import json
import numpy as np
import tensorflow as tf
from data_loader import TrainDataLoader, TestDataLoader
from hyperparams import Hyperparams as H
from paths import Paths as P
from model import transformer_model
from attack import ATTACKS, signed_static_fgsm
from evaluate import evaluate

loss_object = tf.keras.losses.BinaryCrossentropy()


def adversarial_train(adv_bundle, train_loader, source_bundle, epochs=None, training_attack=None):
    if epochs is None:
        epochs = H.num_epochs
    if training_attack is None:
        training_attack = signed_static_fgsm
    for epoch in range(epochs):
        for idx in range(len(train_loader)):
            sample_batch, labels = train_loader[idx]
            adv_batch = training_attack(source_bundle, sample_batch, labels)
            adv_bundle["model"].train_on_batch(adv_batch, labels)


if __name__ == "__main__":
    source_bundle = transformer_model().get_models()
    source_bundle["model"].load_weights(P.saved_model)

    adv_bundle = transformer_model().get_models()
    adv_bundle["model"].compile(
        optimizer=tf.keras.optimizers.Adam(learning_rate=H.learning_rate),
        loss=loss_object,
        metrics=["accuracy"],
    )
    adv_bundle["model"].set_weights(source_bundle["model"].get_weights())

    train_loader = TrainDataLoader()
    test_loader = TestDataLoader()
    adversarial_train(adv_bundle, train_loader, source_bundle, training_attack=signed_static_fgsm)
    adv_bundle["model"].save_weights(P.defended_model)

    results = {}
    for name, fn in ATTACKS.items():
        results[name] = evaluate(adv_bundle, test_loader, attack_fn=fn)
    with open("results_defense.json", "w") as f:
        json.dump(results, f, indent=2)
    print(json.dumps(results, indent=2))
