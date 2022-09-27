import json

with open('DLL_order.json', 'r') as infile:
    dll_ordering_dict_gl = json.loads(infile.read())

with open('strings_order.json', 'r') as infile:
    strings_ordering_dict_gl = json.loads(infile.read())

class Hyperparams:
    #data preprocessing
    vocab_size = 1000
    real_vocab_size = vocab_size + 2 # including padding and rare tag
    num_malicious_files = 3000 #for tokenizer
    dll_feature_len = len(dll_ordering_dict_gl.keys()) #static feature
    strings_feature_len = len(strings_ordering_dict_gl.keys()) #static feature
    static_feature_len = dll_feature_len + strings_feature_len
    
    #model training
    
    #adversarial attack