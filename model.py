import tensorflow as tf 
from tensorflow.keras import Model
from tensorflow.keras.layers import Dense, GlobalAveragePooling1D, Input, Lambda, concatenate
from transformer import Encoder, PaddingMask
from paths import Paths as P 
from hyperparams import Hyperparams as H 

class transformer_model(object):
    def __init__(self):
        None

    def get_model(self):
        inp_exe = Input(shape=(H.executable_size, 3), dtype='int32', name='inp_exe')
        mask = Lambda(lambda x: x[:, :, 0])(inp_exe)
        mask = PaddingMask()(mask)
        print("##############", inp_exe, mask)
        encoding, enc_attention_weights = Encoder(
            num_layers=H.num_layers,
            d_model=H.d_model,
            num_heads=H.num_heads,
            d_ff=H.d_ff,
            vocab_size=H.real_vocab_size,
            dropout_rate=H.dropout_rate)(inp_exe, mask)
        encoding = GlobalAveragePooling1D()(encoding)
        
        inp_static = Input(shape=(H.static_feature_len))
        concatenated_features = concatenate([encoding, inp_static])
        
        layer_256 = Dense(256, activation="relu")(concatenated_features)
        layer_16 = Dense(16, activation="relu")(layer_256)
        result = Dense(1, activation="sigmoid")(layer_16)

        model = Model(inputs=[inp_exe, inp_static], outputs=result)
        model.summary()
        return model