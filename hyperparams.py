import json
import os

_HERE = os.path.dirname(os.path.abspath(__file__))

with open(os.path.join(_HERE, 'DLL_order.json'), 'r') as infile:
    dll_ordering_dict_gl = json.loads(infile.read())

with open(os.path.join(_HERE, 'strings_order.json'), 'r') as infile:
    strings_ordering_dict_gl = json.loads(infile.read())

class Hyperparams:
    #data preprocessing
    vocab_size = 1000
    real_vocab_size = vocab_size + 2 # including padding and rare tag
    num_malicious_files = 3000 #for tokenizer
    dll_feature_len = len(dll_ordering_dict_gl.keys()) #static feature
    strings_feature_len = len(strings_ordering_dict_gl.keys()) #static feature
    static_feature_len = dll_feature_len + strings_feature_len
    executable_size = 2048
    val_test_ratio = 0.2
    test_ratio_in_val_test = 0.5

    #model training
    d_model = 129
    num_heads = 3
    num_layers = 2
    d_ff = 512
    dropout_rate = 0.1
    batch_size = 32
    num_epochs = 10
    learning_rate = 1e-4

    #adversarial attack
    epsilon = 0.6
    attack_budget = 32