import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import classification_report
from sklearn.utils import unique_labels
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, Dropout
import joblib
import os

# ============================================
# Configuration - Update these paths as needed
# ============================================
DATA_PATH = 'data/CICIDS2017.csv'
MODEL_DIR = '../backend/models'
MODEL_NAME = 'mlp_network_intrusion.h5'
SCALER_NAME = 'network_scaler.pkl'
ENCODER_NAME = 'network_label_encoder.pkl'
EPOCHS = 20
BATCH_SIZE = 64


def load_and_preprocess(path):
    """Load and preprocess CICIDS2017 dataset."""
    print("=" * 50)
    print("Loading CICIDS2017 data...")
    print("=" * 50)

    df = pd.read_csv(path)
    print(f"Raw data shape: {df.shape}")
    print(f"Columns: {list(df.columns)}")

    # Clean data
    df = df.replace([np.inf, -np.inf], np.nan)
    df = df.dropna()
    print(f"After cleaning: {df.shape}")

    # Find label column
    label_col = None
    for candidate in ['Attack Type', 'Label', 'label', 'attack_type', 'class']:
        if candidate in df.columns:
            label_col = candidate
            break
    if label_col is None:
        # Fallback: find first string column
        for col in df.columns:
            if df[col].dtype == 'object':
                label_col = col
                break

    if label_col is None:
        print("ERROR: No label column found!")
        print(f"Available columns: {list(df.columns)}")
        return None

    print(f"Using '{label_col}' as target column")
    print(f"Class distribution:\n{df[label_col].value_counts()}")

    # Separate features and labels
    X = df.drop(label_col, axis=1)
    y = df[label_col]

    # Keep only numeric features
    X = X.select_dtypes(include=[np.number])
    print(f"Features: {X.shape[1]} numeric columns")

    # Encode labels
    le = LabelEncoder()
    y_encoded = le.fit_transform(y)
    print(f"Classes ({len(le.classes_)}): {list(le.classes_)}")

    # Scale features
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    return X_scaled, y_encoded, scaler, le


def build_model(input_dim, num_classes):
    """Build MLP model for network intrusion detection."""
    model = Sequential([
        Dense(128, activation='relu', input_shape=(input_dim,)),
        Dropout(0.3),
        Dense(64, activation='relu'),
        Dropout(0.3),
        Dense(32, activation='relu'),
        Dense(num_classes, activation='softmax')
    ])

    model.compile(
        optimizer='adam',
        loss='sparse_categorical_crossentropy',
        metrics=['accuracy']
    )
    model.summary()
    return model


def main():
    # Check dataset
    if not os.path.exists(DATA_PATH):
        print(f"ERROR: Dataset not found at {DATA_PATH}")
        print("Steps to fix:")
        print("1. Download CICIDS2017 from https://www.kaggle.com/datasets/ericanacletoribeiro/cicids2017-cleaned-and-preprocessed")
        print("2. Place the CSV in: training/data/CICIDS2017.csv")
        return

    # Load data
    result = load_and_preprocess(DATA_PATH)
    if result is None:
        return

    X, y, scaler, le = result

    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"\nTrain: {X_train.shape[0]} samples")
    print(f"Test:  {X_test.shape[0]} samples")

    # Build and train model
    model = build_model(X_train.shape[1], len(le.classes_))

    print(f"\nTraining MLP Model ({EPOCHS} epochs)...")
    history = model.fit(
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

    y_pred = np.argmax(model.predict(X_test, verbose=0), axis=-1)

    # Handle missing classes in report
    present_labels = unique_labels(y_test, y_pred)
    target_names = [le.classes_[i] for i in present_labels]
    print(classification_report(y_test, y_pred, labels=present_labels, target_names=target_names))

    # Save model and preprocessors
    os.makedirs(MODEL_DIR, exist_ok=True)
    model.save(os.path.join(MODEL_DIR, MODEL_NAME))
    joblib.dump(scaler, os.path.join(MODEL_DIR, SCALER_NAME))
    joblib.dump(le, os.path.join(MODEL_DIR, ENCODER_NAME))

    print("\n" + "=" * 50)
    print("SAVED FILES:")
    print(f"  Model:      {MODEL_DIR}/{MODEL_NAME}")
    print(f"  Scaler:     {MODEL_DIR}/{SCALER_NAME}")
    print(f"  Encoder:    {MODEL_DIR}/{ENCODER_NAME}")
    print("=" * 50)


if __name__ == "__main__":
    main()
