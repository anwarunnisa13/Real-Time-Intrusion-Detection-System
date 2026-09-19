import os
import joblib
import numpy as np
import shap
import tensorflow as tf


class DetectionEngine:
    def __init__(self):
        self.network_model = None
        self.network_scaler = None
        self.network_encoder = None
        self.log_model = None
        self.log_tokenizer = None
        self.shap_explainer = None
        self.load_models()

    def load_models(self):
        model_dir = os.path.join(os.path.dirname(__file__), 'models')
        try:
            # Load Network MLP
            net_model_path = os.path.join(model_dir, 'mlp_network_intrusion.h5')
            if os.path.exists(net_model_path):
                self.network_model = tf.keras.models.load_model(net_model_path)
                self.network_scaler = joblib.load(os.path.join(model_dir, 'network_scaler.pkl'))
                self.network_encoder = joblib.load(os.path.join(model_dir, 'network_label_encoder.pkl'))

                # Prepare background data for SHAP
                bg = np.random.randn(50, self.network_model.input_shape[1]).astype(np.float32)
                bg_scaled = self.network_scaler.transform(bg)
                self.shap_explainer = shap.DeepExplainer(self.network_model, bg_scaled)
                print(f"[OK] Network MLP loaded: {len(self.network_encoder.classes_)} classes")
            else:
                print("[SKIP] Network MLP not found")

            # Load Log CNN-LSTM
            log_model_path = os.path.join(model_dir, 'cnnlstm_log_anomaly.h5')
            if os.path.exists(log_model_path):
                self.log_model = tf.keras.models.load_model(log_model_path)
                self.log_tokenizer = joblib.load(os.path.join(model_dir, 'log_tokenizer.pkl'))
                print("[OK] Log CNN-LSTM loaded")
            else:
                print("[SKIP] Log CNN-LSTM not found")
        except Exception as e:
            print(f"[ERROR] Loading models: {e}")

    def predict_network(self, features_array):
        """Predict network traffic using MLP model."""
        if self.network_model is None:
            return None, None, None

        try:
            if features_array.ndim == 1:
                features_array = features_array.reshape(1, -1)

            features_scaled = self.network_scaler.transform(features_array)
            prediction = self.network_model.predict(features_scaled, verbose=0)

            pred_class = int(np.argmax(prediction, axis=-1).flatten()[0])
            confidence = float(np.max(prediction))
            label = self.network_encoder.inverse_transform([pred_class])[0]

            # SHAP explanation
            shap_dict = {}
            try:
                shap_values = self.shap_explainer.shap_values(features_scaled)

                feature_names = [f"Feature_{i}" for i in range(features_scaled.shape[1])]
                if hasattr(self.network_scaler, 'feature_names_in_'):
                    feature_names = list(self.network_scaler.feature_names_in_)

                # Handle different SHAP return formats
                if isinstance(shap_values, list):
                    vals = np.array(shap_values[pred_class]).flatten()
                else:
                    vals = np.array(shap_values).flatten()

                # If vals is 2D (samples x features), take first row
                if vals.ndim > 1:
                    vals = vals[0]

                # Top 5 features by absolute impact
                n_features = min(len(vals), len(feature_names))
                vals = vals[:n_features]
                top_indices = np.argsort(np.abs(vals))[::-1][:5]
                shap_dict = {
                    feature_names[i]: round(float(vals[i]), 4)
                    for i in top_indices if i < len(feature_names)
                }
            except Exception as e:
                print(f"[WARN] SHAP explanation failed: {e}")
                shap_dict = {"Info": "SHAP explanation unavailable"}

            return label, confidence, shap_dict

        except Exception as e:
            print(f"[ERROR] Network prediction: {e}")
            return None, None, None

    def predict_log(self, log_text):
        """Predict system log anomaly using CNN-LSTM model."""
        if self.log_model is None:
            return None, None, None

        try:
            seq = self.log_tokenizer.texts_to_sequences([log_text])
            padded = tf.keras.preprocessing.sequence.pad_sequences(
                seq, maxlen=100, padding='post', truncating='post'
            )

            prediction = float(self.log_model.predict(padded, verbose=0)[0][0])

            if prediction > 0.5:
                label = "Anomaly"
                confidence = prediction
                explanation = (
                    f"Log pattern classified as anomalous (confidence: {prediction:.2%}). "
                    f"The sequence structure deviates from normal log patterns."
                )
            else:
                label = "Normal"
                confidence = 1 - prediction
                explanation = (
                    f"Log pattern classified as normal (confidence: {1-prediction:.2%}). "
                    f"The log follows expected patterns."
                )

            return label, confidence, explanation

        except Exception as e:
            print(f"[ERROR] Log prediction: {e}")
            return None, None, None


engine = DetectionEngine()
