import json
import numpy as np
import tensorflow as tf
from data_loader import TestDataLoader
from hyperparams import Hyperparams as H
from paths import Paths as P
from model import transformer_model
from evaluate import evaluate

loss_object = tf.keras.losses.BinaryCrossentropy()


def _ensure_bundle(model_or_bundle):
    if isinstance(model_or_bundle, dict):
        return model_or_bundle
    return {"model": model_or_bundle}


def _static_gradient(model, tokens, static, labels):
    static_v = tf.Variable(static, dtype=tf.float32)
    tokens_t = tf.convert_to_tensor(tokens, dtype=tf.int32)
    labels_t = tf.convert_to_tensor(labels.reshape(-1, 1), dtype=tf.float32)
    with tf.GradientTape() as tape:
        pred = model([tokens_t, static_v], training=False)
        loss = loss_object(labels_t, pred)
    grad = tape.gradient(loss, static_v)
    if grad is None:
        return np.zeros_like(static, dtype=np.float32)
    return grad.numpy()


def monotone_add_attack(model_or_bundle, sample_batch, labels, budget=None):
    bundle = _ensure_bundle(model_or_bundle)
    model = bundle["model"]
    if budget is None:
        budget = H.attack_budget
    tokens, static = sample_batch
    static = static.astype(np.float32).copy()
    labels_flat = labels.reshape(-1)
    is_mal = (labels_flat == 1)
    active = is_mal.copy()
    n = static.shape[0]

    for _ in range(budget):
        if not active.any():
            break
        grad = _static_gradient(model, tokens, static, labels_flat)
        scores = np.where(static == 0, grad, -np.inf)
        flip_idx = scores.argmax(axis=1)
        flip_gain = scores.max(axis=1)
        for i in range(n):
            if not active[i]:
                continue
            if flip_gain[i] <= 0:
                active[i] = False
                continue
            static[i, flip_idx[i]] = 1.0
        probs = model.predict([tokens, static], verbose=0).reshape(-1)
        flipped = (probs < 0.5)
        active = active & (~flipped)
    return [tokens, static.astype(np.int32)]


def signed_static_fgsm(model_or_bundle, sample_batch, labels, epsilon=None):
    bundle = _ensure_bundle(model_or_bundle)
    model = bundle["model"]
    if epsilon is None:
        epsilon = H.epsilon
    tokens, static = sample_batch
    static_f = static.astype(np.float32)
    grad = _static_gradient(model, tokens, static_f, labels.reshape(-1))
    perturbed = static_f + epsilon * np.sign(grad)
    adv = (perturbed >= 0.5).astype(np.int32)
    adv = np.maximum(adv, static.astype(np.int32))
    return [tokens, adv]


def embedding_pgd_attack(bundle, sample_batch, labels, epsilon=None, n_steps=5):
    if not isinstance(bundle, dict) or "embed_model" not in bundle:
        raise ValueError("embedding_pgd_attack requires the model bundle")
    if epsilon is None:
        epsilon = H.epsilon
    embed_model = bundle["embed_model"]
    encode_model = bundle["encode_model"]
    tokens, static = sample_batch
    tokens_t = tf.convert_to_tensor(tokens, dtype=tf.int32)
    static_t = tf.convert_to_tensor(static.astype(np.float32))
    labels_t = tf.convert_to_tensor(labels.reshape(-1, 1), dtype=tf.float32)

    embedded, mask = embed_model(tokens_t, training=False)
    embedded = tf.Variable(embedded)
    base = tf.identity(embedded)
    step_size = epsilon / max(n_steps, 1)
    for _ in range(n_steps):
        with tf.GradientTape() as tape:
            tape.watch(embedded)
            pred = encode_model([embedded, mask, static_t], training=False)
            loss = loss_object(labels_t, pred)
        g = tape.gradient(loss, embedded)
        if g is None:
            break
        embedded.assign(embedded + step_size * tf.sign(g))
        embedded.assign(tf.clip_by_value(embedded, base - epsilon, base + epsilon))
    return {
        "tokens": tokens,
        "static": static,
        "embedded": embedded.numpy(),
        "mask": mask.numpy(),
    }


def hotflip_attack(bundle, sample_batch, labels, budget=None):
    if not isinstance(bundle, dict) or "embedding_layer" not in bundle:
        raise ValueError("hotflip_attack requires the model bundle")
    if budget is None:
        budget = H.attack_budget
    encode_model = bundle["encode_model"]
    embedding_layer = bundle["embedding_layer"]
    W = embedding_layer.embeddings
    tokens, static = sample_batch
    tokens = tokens.astype(np.int32).copy()
    static_t = tf.constant(static.astype(np.float32))
    labels_flat = labels.reshape(-1)
    labels_t = tf.constant(labels_flat.reshape(-1, 1), dtype=tf.float32)
    V = H.real_vocab_size
    n, seq, n_ch = tokens.shape
    is_mal = (labels_flat == 1)
    active = is_mal.copy()

    for _ in range(budget):
        if not active.any():
            break
        tokens_t = tf.constant(tokens, dtype=tf.int32)
        mask_in = tokens_t[:, :, 0]
        mask = tf.cast(tf.math.equal(mask_in, 0), tf.float32)[:, tf.newaxis, tf.newaxis, :]
        one_hot = tf.one_hot(tokens_t, depth=V, dtype=tf.float32)
        with tf.GradientTape() as tape:
            tape.watch(one_hot)
            embed_chans = [tf.tensordot(one_hot[:, :, c, :], W, axes=[[-1], [0]]) for c in range(n_ch)]
            embedded = tf.concat(embed_chans, axis=-1)
            pred = encode_model([embedded, mask, static_t], training=False)
            loss = loss_object(labels_t, pred)
        grad = tape.gradient(loss, one_hot).numpy()
        current = np.take_along_axis(grad, tokens[..., None], axis=-1)
        scores = grad - current
        scores_flat = scores.reshape(n, -1)
        best_idx = scores_flat.argmax(axis=1)
        best_gain = scores_flat.max(axis=1)
        for i in range(n):
            if not active[i] or best_gain[i] <= 0:
                active[i] = False
                continue
            idx = int(best_idx[i])
            new_t = idx % V
            cell = idx // V
            c = cell % n_ch
            pos = cell // n_ch
            tokens[i, pos, c] = new_t
        probs = bundle["model"].predict([tokens, static], verbose=0).reshape(-1)
        active = active & (probs >= 0.5)
    return [tokens, static]


ATTACKS = {
    "signed_static_fgsm": signed_static_fgsm,
    "monotone_add": monotone_add_attack,
    "embedding_pgd": embedding_pgd_attack,
    "hotflip": hotflip_attack,
}


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--attack", choices=list(ATTACKS.keys()), default=None)
    parser.add_argument("--weights", default=P.saved_model)
    parser.add_argument("--out", default="results_attack.json")
    args = parser.parse_args()

    bundle = transformer_model().get_models()
    bundle["model"].load_weights(args.weights)
    loader = TestDataLoader()
    selected = {args.attack: ATTACKS[args.attack]} if args.attack else ATTACKS
    all_results = {}
    for name, fn in selected.items():
        all_results[name] = evaluate(bundle, loader, attack_fn=fn)
    with open(args.out, "w") as f:
        json.dump(all_results, f, indent=2)
    print(json.dumps(all_results, indent=2))
