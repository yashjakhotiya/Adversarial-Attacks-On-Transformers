from paths import Paths as P
from hyperparams import Hyperparams as H
import os, sys
import pefile
import json
import operator
import pandas as pd

def get_file_names(category):
    path = ''
    if category == 'Benign':
        path = P.benign_exe_disassembled
    elif category == 'Malicious':
        path = P.malicious_exe_disassembled
    else:
        return []
    
    files_with_asm = os.listdir(path)
    files_without_asm = [x[:-4] for x in files_with_asm]

    return files_without_asm

# returns the list of all the DLLs imported for the file
def get_import_DLL_from_file(path):
    pe = pefile.PE(path)
    dlls = []
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll_name = entry.dll.decode('utf-8')
        dlls.append(dll_name.lower())
    
    return dlls

# returns 1. a dictionary mapping each DLL to its count
#         2. a dictionary containing mapping each file to the list of DLLs it imported
#         3. a list of all the files for which extraction failed
def extract_import_DLL_from_folder(path, files):
    file_wise_imports = {}
    all_imports = {}
    failed = []

    for idx, filee in enumerate(files):
        print(idx, end=': ')
        file_path = os.path.join(path, filee)
        try:
            dlls = get_import_DLL_from_file(file_path)
            
            for dll in dlls:
                if dll not in all_imports:
                    all_imports[dll] = 1
                else:
                    all_imports[dll] += 1
            file_wise_imports[filee] = dlls
            print(filee)
        except Exception as e:
            failed.append(filee)
            print('Error extracting file:', file_path, ':', e)

    return all_imports, file_wise_imports, failed

def extract_import_DLL_by_category(category):
    if category == 'Benign' or category == 'Malicious':
        files = get_file_names(category)
    else:
        return False

    print('LENGTH:', len(files))
    
    if category == 'Benign':
        all_imports, file_wise_imports, failed = extract_import_DLL_from_folder(P.benign_exe, files)
    elif category == 'Malicious':
        all_imports, file_wise_imports, failed = extract_import_DLL_from_folder(P.malicious_exe, files)
    else:
        return False

    data = {}
    data['DLLs'] = all_imports
    data['Files'] = file_wise_imports
    data['Failed'] = failed

    json_object = json.dumps(data, indent = 4)

    if category == 'Benign':
      
        with open('benign_DLL_imports.json', 'w') as outfile:
            outfile.write(json_object)
    
    elif category == 'Malicious':

        with open('malicious_DLL_imports.json', 'w') as outfile:
            outfile.write(json_object)

    return data


def merge_dlls_imports(benign_dlls, malicious_dlls, threshold):

    merged_dlls = benign_dlls.copy()

    for dll in malicious_dlls:
        if dll not in merged_dlls:
            merged_dlls[dll] = malicious_dlls[dll]
        else:
            merged_dlls[dll] += malicious_dlls[dll]

    merged_dlls = {k: v for k, v in merged_dlls.items() if v >= threshold}

    merged_dlls = dict(sorted(merged_dlls.items(), key=operator.itemgetter(1), reverse=True))
    return merged_dlls


def generate_dataset(benign_dlls_filewise, malicious_dlls_filewise, merged_dlls):
    ordering_dict = {}
    i = 1
    ordering_list = ['FILENAMES']
    for dll in merged_dlls:
        ordering_list.append(dll)
        ordering_dict[dll] = i
        i += 1
    
    ordering_list.append('MALICIOUS?')

    with open('DLL_order.json', 'w') as outfile:
        outfile.write(json.dumps(ordering_dict))
    

    final_feature_list = []
    for dll_files in benign_dlls_filewise:
        feature_list = [0] * len(ordering_list)
        feature_list[0] = 'B' + dll_files
        for dll in benign_dlls_filewise[dll_files]:
            # print(dll)
            if dll in ordering_dict:
                feature_list[ordering_dict[dll]] = 1
        
        # since benign file
        feature_list[-1] = 0
        final_feature_list.append(feature_list)

    for dll_files in malicious_dlls_filewise:
        feature_list = [0] * len(ordering_list)
        feature_list[0] = 'M' + dll_files
        for dll in malicious_dlls_filewise[dll_files]:
            if dll in ordering_dict:
                feature_list[ordering_dict[dll]] = 1
        
        # since malicious file
        feature_list[-1] = 1
        final_feature_list.append(feature_list)

    dataset = pd.DataFrame(final_feature_list, columns=ordering_list)

    return dataset

with open('DLL_order.json', 'r') as infile:
    ordering_dict_gl = json.loads(infile.read())
def get_dll_feature_vector_for_file(path):
    try:
        dlls = get_import_DLL_from_file(path)
    except:
        dlls = []
    feature_list = [0] * H.dll_feature_len
    for dll in dlls:
        if dll in ordering_dict_gl:
            feature_list[ordering_dict_gl[dll]] = 1
    
    # print(feature_list)
    return feature_list


if __name__ == "__main__":
    # benign_json = extract_import_DLL_by_category('Benign')
    # malicious_json = extract_import_DLL_by_category('Malicious')
    
    # benign_file = open('benign_DLL_imports.json', 'r')
    # benign_json = json.loads(benign_file.read())
    # benign_file.close()

    # malicious_file = open('malicious_DLL_imports.json', 'r')
    # malicious_json = json.loads(malicious_file.read())
    # malicious_file.close()

    # merged_dlls = merge_dlls_imports(benign_json['DLLs'], malicious_json['DLLs'], int(100))

    # dataset = generate_dataset(benign_json['Files'], malicious_json['Files'], merged_dlls)

    # dataset.to_csv('DLL_features.csv', index=False)
    print(get_dll_feature_vector_for_file('../dataset/NEW/Benign/exe/123'))