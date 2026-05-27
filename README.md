# Adversarial-Attacks-On-Transformer-Based-Malware-Detector
Exploring vulnerabilities of Transformer-based Malware Detectors to Adversarial Attacks

Please refer our [paper](https://arxiv.org/abs/2210.00008) for background, our approach and the results.

## Setup

```
pip install -r requirements.txt
```

Point `MALWARE_DATASET_ROOT` at a directory laid out as

```
$MALWARE_DATASET_ROOT/
  NEW/
    Benign/exe/                 # original .exe files
    Benign_Disassembled/exe/    # objdump output (run disassembler.py)
    Benign_Tokenized/exe/       # tokenizer.py output
    Malicious/exe/
    Malicious_Disassembled/exe/
    Malicious_Tokenized/exe/
```

`disassembler.py`, `index_generator.py`, `tokenizer.py` produce the tokenized inputs and `count_dict.json`. `DLL_order.json` and `strings_order.json` are committed. Regenerate them via `extract_DLLs.py` and `extract_strings.py` if you change the dataset.

## Run

```
python train.py                  # trains and writes saved_model.weights.h5
python attack.py                 # runs all attacks, writes results_attack.json
python defense.py                # adversarial training, writes results_defense.json
python feature_squeeze.py        # top-K static-feature squeezing, writes results_squeeze.json
```

Each script writes a `results_*.json` with clean accuracy, robust accuracy, and attack success rate over the full test set.

## Attacks

`signed_static_fgsm` is the attack from the paper. Three additional attacks are registered in `attack.ATTACKS`.

- `signed_static_fgsm`. Single-step FGSM on the static feature vector using `H.epsilon`, with a monotone gate that disallows 1 to 0 flips. `H.epsilon` must be at least 0.5 for the threshold at 0.5 to be crossed.
- `monotone_add`. Greedy gradient ascent on the binary static feature vector, restricted to 0 to 1 flips, budget `H.attack_budget` per sample. Corresponds to adding an unused DLL import or pad-string to a PE.
- `embedding_pgd`. K-step L-infinity PGD in the post-embedding tensor space. Operates on a real-valued perturbation.
- `hotflip`. Discrete token attack via one-hot gradient through the embedding, greedy best swap of (position, channel, new_token), budget `H.attack_budget`.

`attack.py`, `defense.py`, and `feature_squeeze.py` each evaluate against all four and write the matrix to a `results_*.json`.

## Cite

Bibtex:

```
@misc{https://doi.org/10.48550/arxiv.2210.00008,
  doi = {10.48550/ARXIV.2210.00008},
  url = {https://arxiv.org/abs/2210.00008},
  author = {Jakhotiya, Yash and Patil, Heramb and Rawlani, Jugal and Mane, Dr. Sunil B.},
  keywords = {Cryptography and Security (cs.CR), Artificial Intelligence (cs.AI), Machine Learning (cs.LG), FOS: Computer and information sciences, FOS: Computer and information sciences},
  title = {Adversarial Attacks on Transformers-Based Malware Detectors},
  publisher = {arXiv},
  year = {2022},
}
```
