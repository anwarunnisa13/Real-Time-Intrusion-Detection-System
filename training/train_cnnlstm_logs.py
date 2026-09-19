import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from tensorflow.keras.models import Model
from tensorflow.keras.layers import Input, Embedding, Conv1D, MaxPooling1D, LSTM, Dense, Dropout
from tensorflow.keras.preprocessing.text import Tokenizer
from tensorflow.keras.preprocessing.sequence import pad_sequences
import joblib
import os

# ============================================
# Configuration - Update these paths as needed
# ============================================
DATA_PATH = 'data/BGL.csv'
MODEL_DIR = '../backend/models'
MODEL_NAME = 'cnnlstm_log_anomaly.h5'
TOKENIZER_NAME = 'log_tokenizer.pkl'
MAX_WORDS = 10000
MAX_LEN = 100
EPOCHS = 10
BATCH_SIZE = 32


def load_and_preprocess(path):
    """Load and preprocess BGL log dataset."""
    print("=" * 50)
    print("Loading BGL Log data...")
    print("=" * 50)

    df = pd.read_csv(path)
    print(f"Raw data shape: {df.shape}")
    print(f"Columns: {list(df.columns)}")

    # Find content column
    content_col = None
    for candidate in ['Content', 'content', 'Log', 'log', 'message']:
        if candidate in df.columns:
            content_col = candidate
            break
    if content_col is None:
        print(f"ERROR: No content column found. Available: {list(df.columns)}")
        return None

    # Find label column
    label_col = None
    for candidate in ['Label', 'label', 'label_type']:
        if candidate in df.columns:
            label_col = candidate
            break
    if label_col is None:
        print(f"ERROR: No label column found. Available: {list(df.columns)}")
        return None

    print(f"Using '{content_col}' as content and '{label_col}' as label")

    # Clean data
    df[content_col] = df[content_col].fillna('')

    # Tokenize log messages
    tokenizer = Tokenizer(num_words=MAX_WORDS, oov_token='<OOV>')
    tokenizer.fit_on_texts(df[content_col])
    sequences = tokenizer.texts_to_sequences(df[content_col])
    X = pad_sequences(sequences, maxlen=MAX_LEN, padding='post', truncating='post')

    # Encode labels: '-' means Normal, anything else is Anomaly
    y = df[label_col].apply(lambda x: 0 if str(x).strip() == '-' else 1).values
    print(f"Normal: {np.sum(y == 0)}, Anomaly: {np.sum(y == 1)}")
    print(f"Vocabulary size: {min(MAX_WORDS, len(tokenizer.word_index) + 1)}")

    return X, y, tokenizer


def build_model(input_length, vocab_size):
    """Build CNN-LSTM model for log anomaly detection."""
    inputs = Input(shape=(input_length,))
    x = Embedding(vocab_size, 64)(inputs)
    x = Conv1D(64, 5, activation='relu')(x)
    x = MaxPooling1D(pool_size=2)(x)
    x = LSTM(64, return_sequences=False)(x)
    x = Dropout(0.5)(x)
    outputs = Dense(1, activation='sigmoid')(x)

    model = Model(inputs=inputs, outputs=outputs)
    model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
    model.summary()
    return model


def main():
    # Check dataset
    if not os.path.exists(DATA_PATH):
        print(f"ERROR: Dataset not found at {DATA_PATH}")
        print("Steps to fix:")
        print("1. Download BGL logs from https://www.kaggle.com/datasets/boltzmannbrain/bgl-logs")
        print("2. Convert to CSV with 'Content' and 'Label' columns")
        print("3. Place in: training/data/BGL.csv")
        return

    # Load data
    result = load_and_preprocess(DATA_PATH)
    if result is None:
        return

    X, y, tokenizer = result

    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"\nTrain: {X_train.shape[0]} samples")
    print(f"Test:  {X_test.shape[0]} samples")

    # Build and train model
    vocab_size = min(MAX_WORDS, len(tokenizer.word_index) + 1)
    model = build_model(MAX_LEN, vocab_size)

    print(f"\nTraining CNN-LSTM Model ({EPOCHS} epochs)...")
    model.fit(
        X_train, y_train,
        epochs=EPOCHS,
        batch_size=BATCH_SIZE,
        validation_split=0.1,
        verbose=1
    )

    # Evaluate
    print("\n" + "=" * 50)
    print("Evaluating Model...")
    print("=" * 50)
    loss, accuracy = model.evaluate(X_test, y_test)
    print(f"Test Accuracy: {accuracy:.4f}")

    y_pred = (model.predict(X_test, verbose=0) > 0.5).astype(int).flatten()
    print(classification_report(y_test, y_pred, target_names=['Normal', 'Anomaly']))

    # Save model and tokenizer
    os.makedirs(MODEL_DIR, exist_ok=True)
    model.save(os.path.join(MODEL_DIR, MODEL_NAME))
    joblib.dump(tokenizer, os.path.join(MODEL_DIR, TOKENIZER_NAME))

    print("\n" + "=" * 50)
    print("SAVED FILES:")
    print(f"  Model:      {MODEL_DIR}/{MODEL_NAME}")
    print(f"  Tokenizer:  {MODEL_DIR}/{TOKENIZER_NAME}")
    print("=" * 50)


if __name__ == "__main__":
    main()
