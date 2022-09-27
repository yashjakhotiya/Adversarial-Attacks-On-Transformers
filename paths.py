import os

class Paths:
    dataset = os.path.join("..", "dataset")
    benign_exe = os.path.join(dataset, "NEW", "Benign", "exe")
    benign_exe_disassembled = os.path.join(dataset, "NEW", "Benign_Disassembled", "exe")
    benign_exe_tokenized = os.path.join(dataset, "NEW", "Benign_Tokenized", "exe")
    malicious_exe = os.path.join(dataset, "NEW", "Malicious", "exe")
    malicious_exe_disassembled = os.path.join(dataset, "NEW", "Malicious_Disassembled", "exe")
    malicious_exe_tokenized = os.path.join(dataset, "NEW", "Malicious_Tokenized", "exe")
    count_dict_json = "count_dict.json"
    saved_model = "saved_model.h5"
