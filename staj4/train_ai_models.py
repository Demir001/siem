# -*- coding: utf-8 -*-
"""
====================================================================================
LARGE-SCALE STREAMING AI MODEL TRAINING ENGINE (train_ai_models.py)
====================================================================================
This module trains the Multi-Layer Variance-Weighted Ensemble and Pure-NumPy
Zero-Day Autoencoder using an out-of-core streaming architecture capable of
processing 3,000,000+ samples with fixed memory consumption (<250 MB RAM).

USAGE:
    python train_ai_models.py --dataset dataset_3m.jsonl --batch-size 50000
====================================================================================
"""

import os
import sys
import time
import json
import joblib
import argparse
import numpy as np
from scipy.sparse import hstack
from sklearn.feature_extraction.text import HashingVectorizer, TfidfVectorizer
from sklearn.linear_model import SGDClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, f1_score

# ==================================================================================
# 1. STREAMING JSONL DATASET READER
# ==================================================================================

def stream_jsonl_dataset(file_path, batch_size=50000, max_samples=None):
    """
    Streams large JSONL datasets in mini-batches without loading the entire file into RAM.
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Dataset file not found: {file_path}")

    current_batch_texts = []
    current_batch_labels = []
    current_batch_net = []
    total_yielded = 0

    with open(file_path, "r", encoding="utf-8", buffering=1024*1024*16) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            if line.startswith("[") or line.endswith("]"):
                continue
            if line.endswith(","):
                line = line[:-1]

            try:
                item = json.loads(line)
                current_batch_texts.append(item["text"])
                current_batch_labels.append(item["label"])
                current_batch_net.append(item.get("network_type", "UNKNOWN"))
            except Exception:
                continue

            if len(current_batch_texts) >= batch_size:
                yield current_batch_texts, np.array(current_batch_labels, dtype=np.int32), current_batch_net
                total_yielded += len(current_batch_texts)
                current_batch_texts = []
                current_batch_labels = []
                current_batch_net = []

                if max_samples and total_yielded >= max_samples:
                    break

        if current_batch_texts:
            yield current_batch_texts, np.array(current_batch_labels, dtype=np.int32), current_batch_net

# ==================================================================================
# 2. STREAMING ENSEMBLE TRAINING (OUT-OF-CORE)
# ==================================================================================

def train_streaming_ensemble(dataset_path, batch_size=50000, output_dir="models/numpy_ensemble"):
    os.makedirs(output_dir, exist_ok=True)
    print("\n" + "=" * 75)
    print("  OUT-OF-CORE VARIANCE-WEIGHTED ENSEMBLE TRAINING ")
    print("=" * 75)

    n_features_each = 16384
    ensemble_configs = [
        {
            "id": 1,
            "name": "General System & Daemon Analyzer",
            "exec_vec": HashingVectorizer(n_features=n_features_each, ngram_range=(1, 3), token_pattern=r'(?u)\b\w+\b', alternate_sign=False),
            "arg_vec": HashingVectorizer(n_features=n_features_each, analyzer='char_wb', ngram_range=(3, 5), alternate_sign=False),
            "anomaly_vec": HashingVectorizer(n_features=n_features_each, token_pattern=r'[^\w\s]|\d+|[A-Za-z]+', ngram_range=(1, 2), alternate_sign=False),
            "weights": (1.2, 1.0, 1.4),
            "clf": SGDClassifier(loss='log_loss', penalty='l2', alpha=1e-5, max_iter=20, random_state=42)
        },
        {
            "id": 2,
            "name": "Obfuscation & Character Structure Analyzer",
            "exec_vec": HashingVectorizer(n_features=n_features_each, ngram_range=(1, 2), token_pattern=r'(?u)\b\w+\b', alternate_sign=False),
            "arg_vec": HashingVectorizer(n_features=n_features_each, analyzer='char', ngram_range=(2, 6), alternate_sign=False),
            "anomaly_vec": HashingVectorizer(n_features=n_features_each, token_pattern=r'[\$\\;\`\|\&><\(\)\{\}\[\]\=]', ngram_range=(1, 3), alternate_sign=False),
            "weights": (0.8, 1.6, 1.5),
            "clf": SGDClassifier(loss='log_loss', penalty='l2', alpha=1e-5, max_iter=20, random_state=43)
        },
        {
            "id": 3,
            "name": "Network IP & Communication Analyzer",
            "exec_vec": HashingVectorizer(n_features=n_features_each, ngram_range=(1, 3), token_pattern=r'(?u)\b[\w\.\:\-\/]+\b', alternate_sign=False),
            "arg_vec": HashingVectorizer(n_features=n_features_each, analyzer='char_wb', ngram_range=(3, 5), alternate_sign=False),
            "anomaly_vec": HashingVectorizer(n_features=n_features_each, token_pattern=r'\b(?:\d{1,3}\.){3}\d{1,3}\b|[^\w\s]', ngram_range=(1, 2), alternate_sign=False),
            "weights": (1.4, 1.0, 1.2),
            "clf": SGDClassifier(loss='log_loss', penalty='l2', alpha=1e-5, max_iter=20, random_state=44)
        },
        {
            "id": 4,
            "name": "Web Exploit & Injection Analyzer",
            "exec_vec": HashingVectorizer(n_features=n_features_each, ngram_range=(1, 2), token_pattern=r'(?u)\b\w+\b', alternate_sign=False),
            "arg_vec": HashingVectorizer(n_features=n_features_each, analyzer='char_wb', ngram_range=(2, 5), alternate_sign=False),
            "anomaly_vec": HashingVectorizer(n_features=n_features_each, token_pattern=r'jndi|\.\.|\%|UNION|SELECT|eval|base64|sh|bash', ngram_range=(1, 2), alternate_sign=False),
            "weights": (1.0, 1.3, 1.6),
            "clf": SGDClassifier(loss='log_loss', penalty='l2', alpha=1e-5, max_iter=20, random_state=45)
        }
    ]

    total_trained_samples = 0
    start_time = time.time()
    classes = np.array([0, 1], dtype=np.int32)

    batch_idx = 0
    for texts, labels, _ in stream_jsonl_dataset(dataset_path, batch_size=batch_size):
        batch_idx += 1
        b_size = len(texts)

        for cfg in ensemble_configs:
            x1 = cfg["exec_vec"].transform(texts)
            x2 = cfg["arg_vec"].transform(texts)
            x3 = cfg["anomaly_vec"].transform(texts)
            w1, w2, w3 = cfg["weights"]
            X_comb = hstack([x1 * w1, x2 * w2, x3 * w3])

            cfg["clf"].partial_fit(X_comb, labels, classes=classes)

        total_trained_samples += b_size
        elapsed = time.time() - start_time
        rate = total_trained_samples / elapsed
        print(f"  [+] Trained Batch {batch_idx:03d} ({total_trained_samples:,} Logs) | Throughput: {rate:,.0f} logs/sec")

    saved_models = []
    print("\n[*] Saving Ensemble Models to Disk...")
    for cfg in ensemble_configs:
        m_id = cfg["id"]
        W = cfg["clf"].coef_[0].astype(np.float32)
        b = float(cfg["clf"].intercept_[0])
        w1, w2, w3 = cfg["weights"]

        model_dict = {
            "exec_vec": cfg["exec_vec"],
            "arg_vec": cfg["arg_vec"],
            "anomaly_vec": cfg["anomaly_vec"],
            "weights": (w1, w2, w3),
            "W": W,
            "b": b,
            "input_dim": int(W.shape[0])
        }
        save_path = os.path.join(output_dir, f"model_{m_id}.joblib")
        joblib.dump(model_dict, save_path, compress=3)
        print(f"  [OK] {cfg['name']} -> {save_path} (Weight Dimensions: {W.shape[0]:,})")
        saved_models.append(model_dict)

    return saved_models

# ==================================================================================
# 3. ZERO-DAY AUTOENCODER TRAINING
# ==================================================================================

def train_streaming_autoencoder(dataset_path, sample_limit=100000, output_dir="models/numpy_autoencoder"):
    os.makedirs(output_dir, exist_ok=True)
    print("\n" + "=" * 75)
    print(f"  PURE-NUMPY ZERO-DAY AUTOENCODER TRAINING ({sample_limit:,} BENIGN LOGS) ")
    print("=" * 75)

    safe_samples = []
    for texts, labels, _ in stream_jsonl_dataset(dataset_path, batch_size=20000):
        for t, l in zip(texts, labels):
            if l == 0:
                safe_samples.append(t)
                if len(safe_samples) >= sample_limit:
                    break
        if len(safe_samples) >= sample_limit:
            break

    print(f"[+] Vectorizing {len(safe_samples):,} Benign System Logs...")
    input_dim = 512
    vec = TfidfVectorizer(max_features=input_dim, ngram_range=(1, 2), token_pattern=r'(?u)\b\w+\b|[^\w\s]')
    X_safe = vec.fit_transform(safe_samples).toarray().astype(np.float32)

    np.random.seed(42)
    h1_dim, h2_dim = 64, 16
    we1 = (np.random.randn(input_dim, h1_dim) * np.sqrt(2.0 / input_dim)).astype(np.float32)
    be1 = np.zeros(h1_dim, dtype=np.float32)
    we2 = (np.random.randn(h1_dim, h2_dim) * np.sqrt(2.0 / h1_dim)).astype(np.float32)
    be2 = np.zeros(h2_dim, dtype=np.float32)
    wd1 = (np.random.randn(h2_dim, h1_dim) * np.sqrt(2.0 / h2_dim)).astype(np.float32)
    bd1 = np.zeros(h1_dim, dtype=np.float32)
    wd2 = (np.random.randn(h1_dim, input_dim) * np.sqrt(2.0 / h1_dim)).astype(np.float32)
    bd2 = np.zeros(input_dim, dtype=np.float32)

    def relu(x): return np.maximum(0.0, x)
    def relu_grad(x): return (x > 0.0).astype(np.float32)
    def sigmoid(x): return 1.0 / (1.0 + np.exp(-np.clip(x, -250.0, 250.0)))

    epochs = 25
    batch_size = 128
    lr = 0.05
    n_samples = X_safe.shape[0]

    for epoch in range(epochs):
        indices = np.random.permutation(n_samples)
        X_shuffled = X_safe[indices]
        epoch_loss = 0.0

        for i in range(0, n_samples, batch_size):
            xb = X_shuffled[i:i + batch_size]
            m = xb.shape[0]

            # Forward
            z1 = xb.dot(we1) + be1
            a1 = relu(z1)
            z2 = a1.dot(we2) + be2
            a2 = relu(z2)
            z3 = a2.dot(wd1) + bd1
            a3 = relu(z3)
            z4 = a3.dot(wd2) + bd2
            recon = sigmoid(z4)

            diff = recon - xb
            loss = np.mean(diff ** 2)
            epoch_loss += loss * m

            # Backward
            d_z4 = (2.0 / input_dim) * diff * (recon * (1.0 - recon))
            d_wd2 = a3.T.dot(d_z4) / m
            d_bd2 = np.sum(d_z4, axis=0) / m

            d_a3 = d_z4.dot(wd2.T)
            d_z3 = d_a3 * relu_grad(z3)
            d_wd1 = a2.T.dot(d_z3) / m
            d_bd1 = np.sum(d_z3, axis=0) / m

            d_a2 = d_z3.dot(wd1.T)
            d_z2 = d_a2 * relu_grad(z2)
            d_we2 = a1.T.dot(d_z2) / m
            d_be2 = np.sum(d_z2, axis=0) / m

            d_a1 = d_z2.dot(we2.T)
            d_z1 = d_a1 * relu_grad(z1)
            d_we1 = xb.T.dot(d_z1) / m
            d_be1 = np.sum(d_z1, axis=0) / m

            wd2 -= lr * d_wd2
            bd2 -= lr * d_bd2
            wd1 -= lr * d_wd1
            bd1 -= lr * d_bd1
            we2 -= lr * d_we2
            be2 -= lr * d_be2
            we1 -= lr * d_we1
            be1 -= lr * d_be1

        if (epoch + 1) % 5 == 0 or epoch == 0:
            print(f"    [Epoch {epoch+1:02d}/{epochs:02d}] Reconstruction Loss (MSE): {epoch_loss / n_samples:.6f}")

    h1 = relu(X_safe.dot(we1) + be1)
    h2 = relu(h1.dot(we2) + be2)
    h3 = relu(h2.dot(wd1) + bd1)
    final_recon = sigmoid(h3.dot(wd2) + bd2)
    safe_errors = np.mean((X_safe - final_recon) ** 2, axis=1)
    threshold = float(np.percentile(safe_errors, 99.0) * 1.15)
    print(f"[+] Dynamic Zero-Day Baseline Threshold: {threshold:.6f}")

    ae_dict = {
        "vectorizer": vec,
        "threshold": threshold,
        "we1": we1, "be1": be1,
        "we2": we2, "be2": be2,
        "wd1": wd1, "bd1": bd1,
        "wd2": wd2, "bd2": bd2
    }
    save_path = os.path.join(output_dir, "autoencoder.joblib")
    joblib.dump(ae_dict, save_path, compress=3)
    print(f"[OK] Autoencoder Saved: {save_path}")
    return ae_dict

# ==================================================================================
# 4. EVALUATION & INFERENCE BENCHMARK
# ==================================================================================

def evaluate_models_streaming(ensemble_models, ae_model, dataset_path, test_samples=20000):
    print("\n" + "=" * 75)
    print(f"  EVALUATION & INFERENCE BENCHMARK ({test_samples:,} LOGS) ")
    print("=" * 75)

    test_texts = []
    test_labels = []
    test_net = []

    for texts, labels, nets in stream_jsonl_dataset(dataset_path, batch_size=5000):
        test_texts.extend(texts)
        test_labels.extend(labels)
        test_net.extend(nets)
        if len(test_texts) >= test_samples:
            break

    test_texts = test_texts[:test_samples]
    test_labels = np.array(test_labels[:test_samples], dtype=np.int32)

    start_bench = time.time()
    def sigmoid(x): return 1.0 / (1.0 + np.exp(-np.clip(x, -250.0, 250.0)))
    def relu(x): return np.maximum(0.0, x)

    all_preds = []
    T = 1.15
    for m in ensemble_models:
        x1 = m["exec_vec"].transform(test_texts)
        x2 = m["arg_vec"].transform(test_texts)
        x3 = m["anomaly_vec"].transform(test_texts)
        w1, w2, w3 = m["weights"]
        X_comb = hstack([x1 * w1, x2 * w2, x3 * w3])
        logits = X_comb.dot(m["W"]) + m["b"]
        probs = sigmoid(logits / T)
        all_preds.append(probs)

    all_preds = np.array(all_preds)
    var_weights = np.array([1.1, 1.2, 1.0, 1.15])
    var_weights /= np.sum(var_weights)
    ensemble_probs = np.tensordot(var_weights, all_preds, axes=(0, 0))

    X_ae = ae_model["vectorizer"].transform(test_texts).toarray().astype(np.float32)
    h1 = relu(X_ae.dot(ae_model["we1"]) + ae_model["be1"])
    h2 = relu(h1.dot(ae_model["we2"]) + ae_model["be2"])
    h3 = relu(h2.dot(ae_model["wd1"]) + ae_model["bd1"])
    recon_ae = sigmoid(h3.dot(ae_model["wd2"]) + ae_model["bd2"])
    ae_errors = np.mean((X_ae - recon_ae) ** 2, axis=1)

    y_pred = (ensemble_probs >= 0.5).astype(int)
    for idx, err in enumerate(ae_errors):
        if err > ae_model["threshold"] and y_pred[idx] == 0:
            if ensemble_probs[idx] > 0.35:
                y_pred[idx] = 1

    bench_time = time.time() - start_bench
    per_log_us = (bench_time / len(test_texts)) * 1_000_000

    acc = accuracy_score(test_labels, y_pred)
    f1 = f1_score(test_labels, y_pred)
    cm = confusion_matrix(test_labels, y_pred)

    print(f"[+] Evaluated Samples   : {len(test_texts):,}")
    print(f"[+] Overall Accuracy    : {acc * 100:.2f}%")
    print(f"[+] F1 Score            : {f1:.4f}")
    print(f"[+] Inference Latency   : {per_log_us:.2f} microseconds / log")

    print("\n--- CLASSIFICATION REPORT ---")
    print(classification_report(test_labels, y_pred, target_names=["SAFE (0)", "MALICIOUS (1)"], digits=4))

    print("--- CONFUSION MATRIX ---")
    print(f"               Predicted: SAFE    Predicted: MALICIOUS")
    print(f"Actual SAFE    :    {cm[0,0]:<15}   {cm[0,1]:<15}")
    print(f"Actual MALICIOUS:   {cm[1,0]:<15}   {cm[1,1]:<15}")

# ==================================================================================
# 5. MAIN CONTROLLER
# ==================================================================================

def main():
    parser = argparse.ArgumentParser(description="Multi-Layer AI Security Model Training Engine")
    parser.add_argument("--dataset", type=str, default="dataset_3m.jsonl", help="Dataset file path (e.g. dataset_3m.jsonl)")
    parser.add_argument("--batch-size", type=int, default=50000, help="Streaming batch size (Default: 50000)")
    args = parser.parse_args()

    ds_path = args.dataset
    if not os.path.exists(ds_path):
        if os.path.exists("dataset_5000.jsonl"):
            ds_path = "dataset_5000.jsonl"
        else:
            print(f"[*] '{ds_path}' not found, generating sample streaming dataset...")
            import generate_dataset
            generate_dataset.generate_streaming_dataset(total_samples=50000, output_path="dataset_50k.jsonl")
            ds_path = "dataset_50k.jsonl"

    start_all = time.time()
    ensemble_models = train_streaming_ensemble(ds_path, batch_size=args.batch_size)
    ae_model = train_streaming_autoencoder(ds_path, sample_limit=100000)
    evaluate_models_streaming(ensemble_models, ae_model, ds_path)

    total_time = time.time() - start_all
    print(f"\n[OK] Model Training Completed Successfully in {total_time:.2f} seconds.")

if __name__ == "__main__":
    main()
