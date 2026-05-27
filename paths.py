import os

_HERE = os.path.dirname(os.path.abspath(__file__))


class Paths:
    dataset = os.environ.get("MALWARE_DATASET_ROOT", os.path.join("..", "dataset"))
    benign_exe = os.path.join(dataset, "NEW", "Benign", "exe")
    benign_exe_disassembled = os.path.join(dataset, "NEW", "Benign_Disassembled", "exe")
    benign_exe_tokenized = os.path.join(dataset, "NEW", "Benign_Tokenized", "exe")
    malicious_exe = os.path.join(dataset, "NEW", "Malicious", "exe")
    malicious_exe_disassembled = os.path.join(dataset, "NEW", "Malicious_Disassembled", "exe")
    malicious_exe_tokenized = os.path.join(dataset, "NEW", "Malicious_Tokenized", "exe")
    count_dict_json = os.path.join(_HERE, "count_dict.json")
    saved_model = os.path.join(_HERE, "saved_model.weights.h5")
    defended_model = os.path.join(_HERE, "defended_model.weights.h5")
