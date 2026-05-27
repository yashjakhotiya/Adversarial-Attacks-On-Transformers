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
        bundle = self.get_models()
        return bundle["model"]

    def get_models(self):
        encoder = Encoder(
            num_layers=H.num_layers,
            d_model=H.d_model,
            num_heads=H.num_heads,
            d_ff=H.d_ff,
            vocab_size=H.real_vocab_size,
            dropout_rate=H.dropout_rate,
        )
        padding_mask = PaddingMask()
        gap = GlobalAveragePooling1D()
        dense_256 = Dense(256, activation="relu")
        dense_16 = Dense(16, activation="relu")
        dense_out = Dense(1, activation="sigmoid")

        inp_exe = Input(shape=(H.executable_size, 3), dtype='int32', name='inp_exe')
        mask_in = Lambda(lambda x: x[:, :, 0])(inp_exe)
        mask = padding_mask(mask_in)
        embedded = encoder.embed_only(inp_exe)
        encoded, _ = encoder.encode_from_embedded(embedded, mask)
        pooled = gap(encoded)
        inp_static = Input(shape=(H.static_feature_len,), name='inp_static')
        cat = concatenate([pooled, inp_static])
        logit = dense_out(dense_16(dense_256(cat)))
        model = Model(inputs=[inp_exe, inp_static], outputs=logit)

        embed_model = Model(inputs=inp_exe, outputs=[embedded, mask])

        inp_embedded = Input(shape=(H.executable_size, H.d_model), name='inp_embedded')
        inp_mask = Input(shape=(1, 1, H.executable_size), name='inp_mask')
        inp_static_e = Input(shape=(H.static_feature_len,), name='inp_static_e')
        encoded_e, _ = encoder.encode_from_embedded(inp_embedded, inp_mask)
        pooled_e = gap(encoded_e)
        cat_e = concatenate([pooled_e, inp_static_e])
        logit_e = dense_out(dense_16(dense_256(cat_e)))
        encode_model = Model(inputs=[inp_embedded, inp_mask, inp_static_e], outputs=logit_e)

        model.summary()
        return {
            "model": model,
            "embed_model": embed_model,
            "encode_model": encode_model,
            "embedding_layer": encoder.embedding,
        }
