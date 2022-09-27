import os
import numpy as np
import tensorflow as tf
from sklearn.model_selection import train_test_split
from hyperparams import Hyperparams as H 
from paths import Paths as P 
from extract_DLLs import get_dll_feature_vector_for_file
from extract_strings import get_string_feature_vector_for_file

benign_files = []
for file in os.listdir(P.benign_exe_tokenized):
    path = os.path.join(P.benign_exe_tokenized, file)
    if os.path.getsize(path) == 0:
        continue
    benign_files.append(path)
print("Length of benign files = {}".format(len(benign_files)))

malicious_files = []
for file in os.listdir(P.malicious_exe_tokenized):
    path = os.path.join(P.malicious_exe_tokenized, file)
    if os.path.getsize(path) == 0:
        continue
    malicious_files.append(path)
print("Length of malicious files = {}".format(len(malicious_files)))

data_files = []
for file in benign_files:
    data_files.append((file, 0))

for file in malicious_files:
    data_files.append((file, 1))

train_files, val_test_files = train_test_split(data_files, test_size=H.val_test_ratio, shuffle=True)
val_files, test_files = train_test_split(val_test_files, test_size=H.test_ratio_in_val_test, shuffle=True)

class TrainDataLoader(tf.keras.utils.Sequence):
    def __init__(self):
        self.batch_size = H.batch_size
        self.num_samples_train = len(train_files)

    def __len__(self):
        return self.num_samples_train // self.batch_size

    def __getitem__(self, idx):
        embedding_batch = []
        static_feature_batch = []
        labels_batch = []
        for i in range(idx*self.batch_size, (idx+1)*self.batch_size):
            single_embedding = []
            with open(train_files[i][0], 'r') as f:
                single_embedding = f.read().split('\n')
            single_embedding = list(map(lambda x: x.split(), single_embedding[:H.executable_size]))
            padding = [[0, 0, 0] for i in range(H.executable_size - len(single_embedding))]
            single_embedding.extend(padding)
            single_embedding = np.array(single_embedding)
            # print(single_embedding.shape)
            # if len(single_embedding.shape) == 1:
            #     print(train_files[i], single_embedding)
            embedding_batch.append(single_embedding)
            
            single_static_feature = get_string_feature_vector_for_file(train_files[i][0]) + get_dll_feature_vector_for_file(train_files[i][0])
            single_static_feature = np.array(single_static_feature)
            static_feature_batch.append(single_static_feature)
            
            labels_batch.append(train_files[i][1])

        embedding_batch = np.array(embedding_batch, dtype='int32')
        static_feature_batch = np.array(static_feature_batch, dtype='int32')
        labels_batch = np.array(labels_batch, dtype='int32')
        # print(embedding_batch.shape)
        return [embedding_batch, static_feature_batch], labels_batch



class ValDataLoader(tf.keras.utils.Sequence):
    def __init__(self):
        self.batch_size = H.batch_size
        self.num_samples_val = len(val_files)

    def __len__(self):
        return self.num_samples_val // self.batch_size

    def __getitem__(self, idx):
        embedding_batch = []
        static_feature_batch = []
        labels_batch = []
        for i in range(idx*self.batch_size, (idx+1)*self.batch_size):
            single_embedding = []
            with open(val_files[i][0], 'r') as f:
                single_embedding = f.read().split('\n')
            single_embedding = list(map(lambda x: x.split(), single_embedding[:H.executable_size]))
            padding = [[0, 0, 0] for i in range(H.executable_size - len(single_embedding))]
            single_embedding.extend(padding)
            embedding_batch.append(single_embedding)

            single_static_feature = get_string_feature_vector_for_file(val_files[i][0]) + get_dll_feature_vector_for_file(val_files[i][0])
            single_static_feature = np.array(single_static_feature)
            static_feature_batch.append(single_static_feature)

            labels_batch.append(val_files[i][1])

        embedding_batch = np.array(embedding_batch, dtype='int32')
        static_feature_batch = np.array(static_feature_batch, dtype='int32')
        labels_batch = np.array(labels_batch, dtype='int32')
        # print(embedding_batch.shape)
        return [embedding_batch, static_feature_batch], labels_batch

class TestDataLoader(tf.keras.utils.Sequence):
    def __init__(self):
        self.batch_size = H.batch_size
        self.num_samples_test = len(test_files)

    def __len__(self):
        return self.num_samples_test // self.batch_size

    def __getitem__(self, idx):
        embedding_batch = []
        static_feature_batch = []
        labels_batch = []
        for i in range(idx*self.batch_size, (idx+1)*self.batch_size):
            single_embedding = []
            with open(test_files[i][0], 'r') as f:
                single_embedding = f.read().split('\n')
            single_embedding = list(map(lambda x: x.split(), single_embedding[:H.executable_size]))
            padding = [[0, 0, 0] for i in range(H.executable_size - len(single_embedding))]
            single_embedding.extend(padding)
            embedding_batch.append(single_embedding)

            single_static_feature = get_string_feature_vector_for_file(test_files[i][0]) + get_dll_feature_vector_for_file(test_files[i][0])
            single_static_feature = np.array(single_static_feature)
            static_feature_batch.append(single_static_feature)

            labels_batch.append(test_files[i][1])

        embedding_batch = np.array(embedding_batch, dtype='int32')
        static_feature_batch = np.array(static_feature_batch, dtype='int32')
        labels_batch = np.array(labels_batch, dtype='int32')
        # print(embedding_batch.shape)
        return [embedding_batch, static_feature_batch], labels_batch
