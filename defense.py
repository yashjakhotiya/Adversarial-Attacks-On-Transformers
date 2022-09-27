import numpy as np
from data_loader import TrainDataLoader
from hyperparams import Hyperparams as H
from paths import Paths as P 
import tensorflow as tf
from model import transformer_model

loss_object = tf.keras.losses.BinaryCrossentropy()
optimizer = tf.keras.optimizers.Adam(learning_rate=H.learning_rate)

adv_model = transformer_model().get_model()
adv_model.compile(optimizer=optimizer,
              loss=loss_object,
              metrics=["accuracy"])

model = transformer_model().get_model()
model.load_weights(P.saved_model)
def create_adversarial_pattern(sample_batch, label_batch, model=model):
    
    sample_batch_tf = [tf.Variable(sample_batch[0], dtype=tf.float32), tf.Variable(sample_batch[1], dtype=tf.float32)]

    with tf.GradientTape() as tape:
        prediction = model(sample_batch_tf)
        
    label_batch = np.reshape(label_batch, newshape=prediction.shape)
    sample_loss = loss_object(label_batch, prediction)
    sample_loss = tf.convert_to_tensor(sample_loss)
    # Get the gradients of the loss w.r.t to the sample batch.
    gradient = tape.gradient(sample_loss, sample_batch_tf, unconnected_gradients='zero')

    # Get the sign of the gradients to create the perturbation
    signed_grad = [tf.sign(gradient[0]), tf.sign(gradient[1])]
    # signed_grad = gradient
    return signed_grad, prediction

train_data_loader = TrainDataLoader()
num_batches = train_data_loader.__len__()

for i in range(num_batches):
    print("Training on batch: {}".format(i))
    sample_batch, label_batch = train_data_loader[i]
    perturbation, prediction = create_adversarial_pattern(sample_batch, label_batch)
    adv_sample_batch = [sample_batch[0] + H.epsilon * perturbation[0], sample_batch[1] + H.epsilon * perturbation[1]]
    adv_model.train_on_batch(adv_sample_batch, label_batch)

perturbation, prediction = create_adversarial_pattern(sample_batch, label_batch, model=adv_model)
adv_sample_batch = [sample_batch[0] + H.epsilon * perturbation[0], sample_batch[1] + H.epsilon * perturbation[1]]
adv_prediction = model.predict(adv_sample_batch)

prediction = [0 if pred < 0.5 else 1 for pred in prediction]
adv_prediction = [0 if pred < 0.5 else 1 for pred in adv_prediction]
misclassification_rate = np.logical_xor(adv_prediction, prediction).sum() / sample_batch[0].shape[0]
print("misclassification rate: {}".format(misclassification_rate))