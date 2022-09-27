import os
import tensorflow as tf
from model import transformer_model
from data_loader import TrainDataLoader, ValDataLoader, TestDataLoader
from paths import Paths as P 
from hyperparams import Hyperparams as H

train_data_loader = TrainDataLoader()
val_data_loader = ValDataLoader()
test_data_loader = TestDataLoader()

optimizer = tf.keras.optimizers.Adam(learning_rate=H.learning_rate)
loss_object = tf.keras.losses.BinaryCrossentropy()

model = transformer_model().get_model()

model.compile(optimizer=optimizer,
              loss=loss_object,
              metrics=["accuracy"])

# model_checkpoint_callback = tf.keras.callbacks.ModelCheckpoint(filepath=os.path.join(P.saved_model_dir, 
# 																		"epoch_{epoch:02d}_val_loss_{val_loss:05.2f}"),
# 															   verbose=1)

print("Starting training... ")
model.fit(train_data_loader, 
		epochs=H.num_epochs, 
		verbose=1, 
		validation_data=val_data_loader,
		max_queue_size=5,
		workers=4,
		use_multiprocessing=False)

print("Saving model... ")
model.save(P.saved_model, save_format='h5')

print("Training done, evaluating on test...")
model.evaluate(test_data_loader,
			max_queue_size=5,
			workers=4,
			use_multiprocessing=False,
			verbose=1)
