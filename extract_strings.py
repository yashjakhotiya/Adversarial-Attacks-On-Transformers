from paths import Paths as P
from hyperparams import Hyperparams as H
import os, sys
from extract_DLLs import get_file_names
import json
import operator
import pandas as pd

def extract_strings_from_file(filename):
    file = open(filename, 'rb')
    data = file.read()
    file.close()

    s = ''
    strings = {}
    for item in data:
        if item >= 32 and item <= 126:
            s += chr(item)
        elif item in (0, 13, 10):
            if len(s) >= 5:
                # print(s)
                if strings.get(s):
                    strings[s] += 1
                else:
                    strings[s] = 1
            s = ''
        else:
            s = ''
        
    return strings

def extract_strings_from_folder(path, files):
    file_wise_strings = {}
    all_strings = {}
    failed = []

    for idx, filee in enumerate(files):
        print(idx, end=': ')
        file_path = os.path.join(path, filee)

        try:
            strings  = extract_strings_from_file(file_path)

            for string in strings:
                if all_strings.get(string):
                    all_strings[string] += strings[string]
                else:
                    all_strings[string] = strings[string]
            
            file_wise_strings[filee] = strings.copy()
            file_wise_strings[filee] = dict(sorted(file_wise_strings[filee].items(), key=operator.itemgetter(1),reverse=True))
            print(filee)
        
        except Exception as e:
            failed.append(filee)
            print('Error extracting file:', file_path, ':', e)

    return all_strings, file_wise_strings, failed

def extract_strings_by_category(category):
    if category == 'Benign' or category == 'Malicious':
        files = get_file_names(category)
    else:
        return False
    files = files
    print('LENGTH:', len(files))

    if category == 'Benign':
        all_imports, file_wise_imports, failed = extract_strings_from_folder(P.benign_exe, files)
    elif category == 'Malicious':
        all_imports, file_wise_imports, failed = extract_strings_from_folder(P.malicious_exe, files)
    else:
        return False

    data = {}
    data['Strings'] = dict(sorted(all_imports.items(), key=operator.itemgetter(1),reverse=True))
    data['Files'] = file_wise_imports
    data['Failed'] = failed

    json_object = json.dumps(data, indent = 4)

    if category == 'Benign':
        with open('benign_strings.json', 'w') as outfile:
            outfile.write(json_object)

    elif category == 'Malicious':
        with open('malicious_strings.json', 'w') as outfile:
            outfile.write(json_object)
    
    return data

def merge_strings(benign_strings, malicious_strings, threshold):

    merged_strings = benign_strings.copy()

    for string in malicious_strings:
        if string not in merged_strings:
            merged_strings[string] = malicious_strings[string]
        else:
            merged_strings[string] += malicious_strings[string]

    merged_strings = {k: v for k, v in merged_strings.items() if v >= threshold}

    merged_strings = dict(sorted(merged_strings.items(), key=operator.itemgetter(1), reverse=True))
    return merged_strings

def generate_dataset(benign_strings_filewise, malicious_strings_filewise, merged_strings):
    ordering_dict = {}
    i = 1
    ordering_list = ['FILENAMES']
    for string in merged_strings:
        ordering_list.append(string)
        ordering_dict[string] = i
        i += 1
    
    ordering_list.append('MALICIOUS?')

    with open('strings_order.json', 'w') as outfile:
        outfile.write(json.dumps(ordering_dict))
    

    final_feature_list = []
    for string_files in benign_strings_filewise:
        feature_list = [0] * len(ordering_list)
        feature_list[0] = 'B' + string_files
        for string in benign_strings_filewise[string_files]:
            # print(string)
            if string in ordering_dict:
                feature_list[ordering_dict[string]] = benign_strings_filewise[string_files][string]
        
        # since benign file
        feature_list[-1] = 0
        final_feature_list.append(feature_list)

    for string_files in malicious_strings_filewise:
        feature_list = [0] * len(ordering_list)
        feature_list[0] = 'M' + string_files
        for string in malicious_strings_filewise[string_files]:
            if string in ordering_dict:
                feature_list[ordering_dict[string]] = malicious_strings_filewise[string_files][string]
        
        # since malicious file
        feature_list[-1] = 1
        final_feature_list.append(feature_list)

    dataset = pd.DataFrame(final_feature_list, columns=ordering_list)

    return dataset

with open('strings_order.json', 'r') as infile:
    ordering_dict_gl = json.loads(infile.read())
def get_string_feature_vector_for_file(path):
    strings = extract_strings_from_file(path)
    feature_list = [0] * H.strings_feature_len
    for string in strings:
        if string in ordering_dict_gl:
            feature_list[ordering_dict_gl[string]] = 1
    
    # print(feature_list)
    return feature_list

if __name__ == "__main__":
 
    # benign_json = extract_strings_by_category('Benign')
    # malicious_json = extract_strings_by_category('Malicious')
    
    # benign_file = open('benign_strings.json', 'r')
    # benign_json = json.loads(benign_file.read())
    # benign_file.close()

    # malicious_file = open('malicious_strings.json', 'r')
    # malicious_json = json.loads(malicious_file.read())
    # malicious_file.close()

    # merged_strings = merge_strings(benign_json['Strings'], malicious_json['Strings'], int(800))

    # dataset = generate_dataset(benign_json['Files'], malicious_json['Files'], merged_strings)

    # dataset.to_csv('strings_features.csv', index=False)
    print(get_string_feature_vector_for_file('../dataset/NEW/Malicious/exe/1003'))