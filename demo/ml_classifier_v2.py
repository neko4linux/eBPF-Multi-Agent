"""
eBPF Multi-Agent Anomaly Detection — 增强版 ML 分类器 v2
==========================================================
新增:
  - 马尔可夫转移矩阵特征
  - TF-IDF 系统调用频率
  - 滑动窗口异常检测
  - 特征重要性分析
  - 混淆矩阵可视化
"""

import os
import sys
import json
import time
import numpy as np
import joblib
from pathlib import Path
from collections import Counter

from sklearn.ensemble import (
    RandomForestClassifier, GradientBoostingClassifier,
    VotingClassifier, IsolationForest, AdaBoostClassifier,
)
from sklearn.linear_model import LogisticRegression
from sklearn.neural_network import MLPClassifier
from sklearn.model_selection import (
    StratifiedKFold, cross_val_score, train_test_split,
)
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import (
    classification_report, confusion_matrix,
    accuracy_score, f1_score, roc_auc_score, roc_curve,
)
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.font_manager as fm


# ═══════════════════════════════════════════
#  常量
# ═══════════════════════════════════════════

DATA_DIR = Path(__file__).parent / "data" / "ADFA-LD"
MODEL_DIR = Path(__file__).parent / "models"
MODEL_DIR.mkdir(exist_ok=True)
FIGURE_DIR = Path(__file__).parent / "figures"
FIGURE_DIR.mkdir(exist_ok=True)

ATTACK_TYPES = {
    "Adduser":          "SHELL_SPAWN",
    "Hydra_FTP":        "HIGH_FREQ_API",
    "Hydra_SSH":        "HIGH_FREQ_API",
    "Java_Meterpreter": "SUSPICIOUS_NETWORK",
    "Meterpreter":      "SUSPICIOUS_NETWORK",
    "Web_Shell":        "SHELL_SPAWN",
}

# 常见系统调用 ID (用于统计分布)
COMMON_SYSCALLS = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
    16, 17, 19, 20, 21, 22, 24, 32, 33, 35, 39, 41, 42,
    43, 44, 45, 46, 47, 49, 50, 56, 57, 58, 59, 60, 61,
    62, 63, 72, 78, 79, 80, 82, 83, 84, 87, 89, 90, 92,
    95, 99, 102, 104, 107, 108, 158, 217, 231, 257, 262,
    263, 288, 292, 302, 318,
]

N_GRAM_SIZES = [2, 3, 5]
TOP_K_NGRAMS = 150
MARKOV_SIZE = 50  # 转移矩阵大小 (取 top N syscall)


# ═══════════════════════════════════════════
#  数据加载
# ═══════════════════════════════════════════

def load_syscall_sequences(directory: Path, label: int) -> list:
    sequences = []
    if not directory.exists():
        return sequences
    for f in sorted(directory.glob("*.txt")):
        try:
            nums = [int(x) for x in f.read_text().strip().split() if x.isdigit()]
            if len(nums) > 5:
                sequences.append((nums, label, f.name))
        except (ValueError, OSError):
            continue
    return sequences


def load_adfa_dataset() -> dict:
    print("[数据] 加载 ADFA-LD 数据集...")
    normal_train = load_syscall_sequences(DATA_DIR / "Training_Data_Master", 0)
    normal_val = load_syscall_sequences(DATA_DIR / "Validation_Data_Master", 0)
    attack_all = []
    attack_dir = DATA_DIR / "Attack_Data_Master"
    if attack_dir.exists():
        for d in sorted(attack_dir.iterdir()):
            if d.is_dir():
                base = d.name.rstrip("0123456789").rstrip("_")
                for seq, label, fname in load_syscall_sequences(d, 1):
                    attack_all.append((seq, label, fname, base))
    print(f"  正常: 训练={len(normal_train)}, 验证={len(normal_val)}")
    print(f"  攻击: {len(attack_all)}")
    for atype, cnt in Counter(a[3] for a in attack_all).most_common():
        print(f"    {atype}: {cnt}")
    return {"normal_train": normal_train, "normal_val": normal_val, "attacks": attack_all}


# ═══════════════════════════════════════════
#  特征工程 v2
# ═══════════════════════════════════════════

def extract_ngram_features(sequences, ngram_sizes=N_GRAM_SIZES, top_k=TOP_K_NGRAMS):
    """n-gram 频率特征"""
    all_ngrams = Counter()
    seq_ngram_counts = []
    for seq, label, *rest in sequences:
        counts = {}
        for n in ngram_sizes:
            for i in range(len(seq) - n + 1):
                ng = tuple(seq[i:i + n])
                counts[ng] = counts.get(ng, 0) + 1
        seq_ngram_counts.append(counts)
        all_ngrams.update(counts)

    top_ngrams = [ng for ng, _ in all_ngrams.most_common(top_k)]
    X = np.zeros((len(sequences), top_k), dtype=np.float32)
    for i, counts in enumerate(seq_ngram_counts):
        seq_len = max(len(sequences[i][0]), 1)
        for j, ng in enumerate(top_ngrams):
            X[i, j] = counts.get(ng, 0) / seq_len
    return X, top_ngrams


def extract_markov_features(sequences, size=MARKOV_SIZE):
    """马尔可夫转移矩阵特征 — 捕获系统调用之间的转移概率"""
    # 确定 top N 系统调用
    all_calls = Counter()
    for seq, *_ in sequences:
        all_calls.update(seq)
    top_calls = [c for c, _ in all_calls.most_common(size)]
    call_to_idx = {c: i for i, c in enumerate(top_calls)}

    n_features = size * size  # 转移矩阵展平
    X = np.zeros((len(sequences), n_features), dtype=np.float32)

    for i, (seq, *_) in enumerate(sequences):
        # 构建转移矩阵
        trans = np.zeros((size, size), dtype=np.float32)
        for j in range(len(seq) - 1):
            if seq[j] in call_to_idx and seq[j + 1] in call_to_idx:
                r = call_to_idx[seq[j]]
                c = call_to_idx[seq[j + 1]]
                trans[r, c] += 1

        # 行归一化
        row_sums = trans.sum(axis=1, keepdims=True)
        row_sums[row_sums == 0] = 1
        trans /= row_sums

        X[i, :] = trans.flatten()

    return X


def extract_statistical_features(sequences):
    """统计特征"""
    n_features = 60
    X = np.zeros((len(sequences), n_features), dtype=np.float32)

    for i, (seq, *_) in enumerate(sequences):
        if not seq:
            continue
        X[i, 0] = len(seq)
        X[i, 1] = len(set(seq))
        X[i, 2] = len(set(seq)) / max(len(seq), 1)

        # 熵
        freq = Counter(seq)
        total = len(seq)
        entropy = -sum((c / total) * np.log2(c / total) for c in freq.values())
        X[i, 3] = entropy

        # 系统调用频率分布
        for j, sc in enumerate(COMMON_SYSCALLS[:56]):
            if j + 4 < n_features:
                X[i, j + 4] = freq.get(sc, 0) / total

    return X


def extract_transition_entropy(sequences):
    """转移熵 — 衡量系统调用序列的随机性"""
    X = np.zeros((len(sequences), 5), dtype=np.float32)
    for i, (seq, *_) in enumerate(sequences):
        if len(seq) < 3:
            continue
        # 二元组频率
        bigrams = Counter(zip(seq[:-1], seq[1:]))
        total_bg = sum(bigrams.values())
        if total_bg > 0:
            X[i, 0] = -sum((c / total_bg) * np.log2(c / total_bg) for c in bigrams.values())

        # 三元组频率
        trigrams = Counter(zip(seq[:-2], seq[1:-1], seq[2:]))
        total_tg = sum(trigrams.values())
        if total_tg > 0:
            X[i, 1] = -sum((c / total_tg) * np.log2(c / total_tg) for c in trigrams.values())

        # 短期重复率 (连续相同调用)
        repeats = sum(1 for j in range(len(seq) - 1) if seq[j] == seq[j + 1])
        X[i, 2] = repeats / max(len(seq) - 1, 1)

        # 调用多样性 (unique / total) 的滑动窗口方差
        window_size = 50
        if len(seq) >= window_size:
            diversities = []
            for start in range(0, len(seq) - window_size + 1, window_size // 2):
                window = seq[start:start + window_size]
                diversities.append(len(set(window)) / window_size)
            X[i, 3] = np.std(diversities) if len(diversities) > 1 else 0
            X[i, 4] = np.mean(diversities)
        else:
            X[i, 3] = 0
            X[i, 4] = len(set(seq)) / max(len(seq), 1)

    return X


def build_features_v2(sequences):
    """组合所有特征 v2"""
    print("  提取 n-gram 特征...", end=" ")
    X_ngram, ngram_names = extract_ngram_features(sequences)
    print(f"dim={X_ngram.shape[1]}")

    print("  提取马尔可夫转移特征...", end=" ")
    X_markov = extract_markov_features(sequences)
    print(f"dim={X_markov.shape[1]}")

    print("  提取统计特征...", end=" ")
    X_stat = extract_statistical_features(sequences)
    print(f"dim={X_stat.shape[1]}")

    print("  提取转移熵特征...", end=" ")
    X_entropy = extract_transition_entropy(sequences)
    print(f"dim={X_entropy.shape[1]}")

    X = np.hstack([X_ngram, X_markov, X_stat, X_entropy])
    y = np.array([s[1] for s in sequences])
    print(f"  总特征维度: {X.shape[1]}")
    return X, y, ngram_names


# ═══════════════════════════════════════════
#  模型训练
# ═══════════════════════════════════════════

def train_models_v2(X_train, y_train, X_test, y_test):
    print("\n[训练] 训练分类器...")
    models = {
        "RandomForest": RandomForestClassifier(
            n_estimators=300, max_depth=20, min_samples_split=3,
            class_weight="balanced", random_state=42, n_jobs=-1,
        ),
        "GradientBoosting": GradientBoostingClassifier(
            n_estimators=200, max_depth=8, learning_rate=0.1,
            subsample=0.8, random_state=42,
        ),
        "AdaBoost": AdaBoostClassifier(
            n_estimators=200, learning_rate=0.1, random_state=42,
        ),
        "LogisticRegression": Pipeline([
            ("scaler", StandardScaler()),
            ("clf", LogisticRegression(max_iter=2000, class_weight="balanced", random_state=42)),
        ]),
        "MLP": Pipeline([
            ("scaler", StandardScaler()),
            ("clf", MLPClassifier(
                hidden_layer_sizes=(256, 128, 64), max_iter=500,
                early_stopping=True, validation_fraction=0.15,
                random_state=42,
            )),
        ]),
    }
    results = {}
    for name, model in models.items():
        print(f"  {name}...", end=" ")
        t0 = time.time()
        model.fit(X_train, y_train)
        y_pred = model.predict(X_test)
        y_proba = None
        if hasattr(model, "predict_proba"):
            y_proba = model.predict_proba(X_test)[:, 1]
        acc = accuracy_score(y_test, y_pred)
        f1 = f1_score(y_test, y_pred, average="weighted")
        auc = roc_auc_score(y_test, y_proba) if y_proba is not None else 0
        elapsed = time.time() - t0
        results[name] = {
            "model": model, "accuracy": acc, "f1": f1,
            "auc": auc, "time": elapsed, "y_pred": y_pred, "y_proba": y_proba,
        }
        print(f"Acc={acc:.4f}  F1={f1:.4f}  AUC={auc:.4f}  ({elapsed:.1f}s)")
    return results


def build_ensemble_v2(results, X_train, y_train):
    print("\n[训练] 构建集成模型...")
    estimators = []
    for name in ["RandomForest", "GradientBoosting", "MLP"]:
        if name in results:
            estimators.append((name, results[name]["model"]))
    ensemble = VotingClassifier(estimators=estimators, voting="soft", n_jobs=-1)
    ensemble.fit(X_train, y_train)
    return ensemble


def train_attack_classifier_v2(dataset):
    print("\n[训练] 训练攻击类型分类器...")
    attacks = dataset["attacks"]
    if len(attacks) < 10:
        return None, None

    labels = []
    valid = []
    for seq, label, fname, atype in attacks:
        if atype in ATTACK_TYPES:
            labels.append(ATTACK_TYPES[atype])
            valid.append((seq, 1, fname))

    if len(set(labels)) < 2:
        return None, None

    normal = dataset["normal_train"][:300]
    for seq, label, fname in normal:
        valid.append((seq, 0, fname))
        labels.append("NORMAL")

    X, _, _ = build_features_v2(valid)
    le = LabelEncoder()
    y = le.fit_transform(labels)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y,
    )
    clf = Pipeline([
        ("scaler", StandardScaler()),
        ("clf", RandomForestClassifier(
            n_estimators=300, max_depth=20,
            class_weight="balanced", random_state=42, n_jobs=-1,
        )),
    ])
    clf.fit(X_train, y_train)
    y_pred = clf.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    print(f"  攻击分类 Accuracy: {acc:.4f}")
    print(f"  类别: {list(le.classes_)}")
    print(classification_report(y_test, y_pred, target_names=le.classes_))
    return clf, le


# ═══════════════════════════════════════════
#  可视化
# ═══════════════════════════════════════════

def plot_roc_curves(results, y_test):
    """绘制 ROC 曲线"""
    fig, ax = plt.subplots(figsize=(10, 8))
    for name, r in results.items():
        if r["y_proba"] is not None:
            fpr, tpr, _ = roc_curve(y_test, r["y_proba"])
            ax.plot(fpr, tpr, label=f'{name} (AUC={r["auc"]:.3f})', linewidth=2)
    ax.plot([0, 1], [0, 1], 'k--', linewidth=1)
    ax.set_xlabel('False Positive Rate', fontsize=12)
    ax.set_ylabel('True Positive Rate', fontsize=12)
    ax.set_title('ROC Curves - Model Comparison', fontsize=14)
    ax.legend(fontsize=11)
    ax.grid(True, alpha=0.3)
    path = FIGURE_DIR / "roc_curves.png"
    fig.savefig(path, dpi=150, bbox_inches='tight')
    plt.close(fig)
    print(f"  ROC 曲线已保存: {path}")


def plot_confusion_matrices(results, y_test):
    """绘制混淆矩阵"""
    fig, axes = plt.subplots(1, len(results), figsize=(5 * len(results), 4))
    if len(results) == 1:
        axes = [axes]
    for ax, (name, r) in zip(axes, results.items()):
        cm = confusion_matrix(y_test, r["y_pred"])
        im = ax.imshow(cm, cmap='Blues')
        ax.set_title(f'{name}\nAcc={r["accuracy"]:.3f}', fontsize=11)
        ax.set_xlabel('Predicted')
        ax.set_ylabel('Actual')
        ax.set_xticks([0, 1])
        ax.set_yticks([0, 1])
        ax.set_xticklabels(['Normal', 'Anomaly'])
        ax.set_yticklabels(['Normal', 'Anomaly'])
        for i in range(2):
            for j in range(2):
                ax.text(j, i, str(cm[i, j]), ha='center', va='center',
                        fontsize=14, color='white' if cm[i, j] > cm.max() / 2 else 'black')
    fig.suptitle('Confusion Matrices', fontsize=14, y=1.02)
    fig.tight_layout()
    path = FIGURE_DIR / "confusion_matrices.png"
    fig.savefig(path, dpi=150, bbox_inches='tight')
    plt.close(fig)
    print(f"  混淆矩阵已保存: {path}")


def plot_feature_importance(ensemble, feature_names, top_n=20):
    """绘制特征重要性"""
    # 从 RandomForest 获取特征重要性
    rf = None
    for name, estimator in ensemble.named_estimators_.items():
        if name == "RandomForest":
            rf = estimator
            break
    if rf is None:
        return

    importances = rf.feature_importances_
    indices = np.argsort(importances)[-top_n:]

    fig, ax = plt.subplots(figsize=(10, 8))
    ax.barh(range(top_n), importances[indices], color='steelblue')
    ax.set_yticks(range(top_n))
    if feature_names and len(feature_names) >= len(indices):
        labels = []
        for idx in indices:
            if idx < len(feature_names):
                ng = feature_names[idx]
                if isinstance(ng, tuple):
                    labels.append(f"ngram_{'-'.join(map(str, ng))}")
                else:
                    labels.append(str(ng))
            else:
                labels.append(f"feature_{idx}")
        ax.set_yticklabels(labels, fontsize=9)
    else:
        ax.set_yticklabels([f"f_{i}" for i in indices], fontsize=9)
    ax.set_xlabel('Feature Importance', fontsize=12)
    ax.set_title(f'Top {top_n} Feature Importances (RandomForest)', fontsize=14)
    ax.grid(True, alpha=0.3, axis='x')
    fig.tight_layout()
    path = FIGURE_DIR / "feature_importance.png"
    fig.savefig(path, dpi=150, bbox_inches='tight')
    plt.close(fig)
    print(f"  特征重要性已保存: {path}")


def plot_model_comparison(results):
    """模型对比柱状图"""
    names = list(results.keys())
    accs = [results[n]["accuracy"] for n in names]
    f1s = [results[n]["f1"] for n in names]
    aucs = [results[n]["auc"] for n in names]

    x = np.arange(len(names))
    width = 0.25

    fig, ax = plt.subplots(figsize=(12, 6))
    bars1 = ax.bar(x - width, accs, width, label='Accuracy', color='steelblue')
    bars2 = ax.bar(x, f1s, width, label='F1-Score', color='coral')
    bars3 = ax.bar(x + width, aucs, width, label='AUC-ROC', color='forestgreen')

    ax.set_ylabel('Score', fontsize=12)
    ax.set_title('Model Performance Comparison', fontsize=14)
    ax.set_xticks(x)
    ax.set_xticklabels(names, rotation=15, ha='right')
    ax.legend(fontsize=11)
    ax.set_ylim(0.85, 1.0)
    ax.grid(True, alpha=0.3, axis='y')

    # 标注数值
    for bars in [bars1, bars2, bars3]:
        for bar in bars:
            height = bar.get_height()
            ax.annotate(f'{height:.3f}',
                        xy=(bar.get_x() + bar.get_width() / 2, height),
                        xytext=(0, 3), textcoords="offset points",
                        ha='center', va='bottom', fontsize=8)

    fig.tight_layout()
    path = FIGURE_DIR / "model_comparison.png"
    fig.savefig(path, dpi=150, bbox_inches='tight')
    plt.close(fig)
    print(f"  模型对比已保存: {path}")


# ═══════════════════════════════════════════
#  模型保存/加载
# ═══════════════════════════════════════════

def save_models_v2(ensemble, iso_forest, attack_clf, attack_le, feature_names):
    print(f"\n[保存] 模型保存到 {MODEL_DIR}/")
    joblib.dump(ensemble, MODEL_DIR / "ensemble.pkl")
    joblib.dump(iso_forest, MODEL_DIR / "isolation_forest.pkl")
    if attack_clf:
        joblib.dump(attack_clf, MODEL_DIR / "attack_classifier.pkl")
        joblib.dump(attack_le, MODEL_DIR / "attack_label_encoder.pkl")
    joblib.dump(feature_names, MODEL_DIR / "feature_names.json")
    print("  ✅ 所有模型已保存")


def load_models() -> dict:
    models = {}
    for name, fname in [
        ("ensemble", "ensemble.pkl"),
        ("isolation_forest", "isolation_forest.pkl"),
        ("attack_classifier", "attack_classifier.pkl"),
        ("attack_label_encoder", "attack_label_encoder.pkl"),
        ("feature_names", "feature_names.json"),
    ]:
        path = MODEL_DIR / fname
        if path.exists():
            models[name] = joblib.load(path)
    return models


# ═══════════════════════════════════════════
#  推理接口
# ═══════════════════════════════════════════

class BehaviorClassifier:
    def __init__(self, models: dict = None):
        self.models = models or {}
        self.ready = bool(self.models.get("ensemble"))

    @classmethod
    def from_disk(cls):
        return cls(load_models())

    def classify(self, syscall_seq: list) -> dict:
        if not self.ready:
            return {"is_anomaly": None, "confidence": 0, "error": "模型未加载"}

        seq_data = [(syscall_seq, 0, "live")]
        X, _, _ = build_features_v2(seq_data)

        ensemble = self.models["ensemble"]
        proba = ensemble.predict_proba(X)[0]
        is_anomaly = proba[1] > 0.5
        confidence = max(proba)

        result = {
            "is_anomaly": bool(is_anomaly),
            "confidence": float(confidence),
            "normal_prob": float(proba[0]),
            "anomaly_prob": float(proba[1]),
            "anomaly_type": "UNKNOWN",
        }

        if "isolation_forest" in self.models:
            iso = self.models["isolation_forest"]
            iso_pred = iso.predict(X)[0]
            result["iso_anomaly"] = bool(iso_pred == -1)
            result["iso_score"] = float(iso.decision_function(X)[0])

        if is_anomaly and "attack_classifier" in self.models:
            atk_clf = self.models["attack_classifier"]
            atk_le = self.models["attack_label_encoder"]
            atk_pred = atk_clf.predict(X)[0]
            result["anomaly_type"] = atk_le.inverse_transform([atk_pred])[0]
            result["type_confidence"] = float(max(atk_clf.predict_proba(X)[0]))

        return result

    def classify_sliding_window(self, syscall_seq, window_size=200, step=50):
        results = []
        for start in range(0, len(syscall_seq) - window_size + 1, step):
            window = syscall_seq[start:start + window_size]
            r = self.classify(window)
            r["window_start"] = start
            r["window_end"] = start + window_size
            results.append(r)
        return results


# ═══════════════════════════════════════════
#  主训练流程
# ═══════════════════════════════════════════

def run_training():
    print("╔══════════════════════════════════════════════════════╗")
    print("║  eBPF Multi-Agent ML 行为分类器 v2                   ║")
    print("║  特征: n-gram + Markov + 统计 + 转移熵              ║")
    print("╚══════════════════════════════════════════════════════╝\n")

    dataset = load_adfa_dataset()
    all_normal = dataset["normal_train"] + dataset["normal_val"]
    all_attacks = [(s, l, f) for s, l, f, _ in dataset["attacks"]]

    n_normal = min(len(all_normal), 2000)
    n_attack = min(len(all_attacks), 2000)
    balanced = all_normal[:n_normal] + all_attacks[:n_attack]
    print(f"\n[特征] 构建特征矩阵 (平衡采样: 正常={n_normal}, 攻击={n_attack})...")

    X, y, feature_names = build_features_v2(balanced)
    print(f"  标签分布: Normal={sum(y == 0)}, Anomaly={sum(y == 1)}")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y,
    )
    print(f"  训练集: {X_train.shape[0]}, 测试集: {X_test.shape[0]}")

    results = train_models_v2(X_train, y_train, X_test, y_test)

    # 评估
    best_name = max(results, key=lambda k: results[k]["f1"])
    best = results[best_name]
    print(f"\n{'=' * 60}")
    print(f"🏆 最佳模型: {best_name}")
    print(f"   Accuracy: {best['accuracy']:.4f}")
    print(f"   F1-Score: {best['f1']:.4f}")
    print(f"   AUC-ROC:  {best['auc']:.4f}")
    print(f"\n📊 分类报告:")
    print(classification_report(y_test, best["y_pred"], target_names=["Normal", "Anomaly"]))

    # CV
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    scores = cross_val_score(best["model"], X_test, y_test, cv=cv, scoring="f1_weighted", n_jobs=-1)
    print(f"📈 5-fold CV: F1={scores.mean():.4f} ± {scores.std():.4f}")

    # 集成
    ensemble = build_ensemble_v2(results, X_train, y_train)
    y_pred_ens = ensemble.predict(X_test)
    y_proba_ens = ensemble.predict_proba(X_test)[:, 1]
    ens_acc = accuracy_score(y_test, y_pred_ens)
    ens_auc = roc_auc_score(y_test, y_proba_ens)
    print(f"\n[集成] Ensemble: Acc={ens_acc:.4f}, AUC={ens_auc:.4f}")

    # Isolation Forest
    print("\n[训练] Isolation Forest...")
    iso = IsolationForest(n_estimators=300, contamination=0.1, random_state=42, n_jobs=-1)
    iso.fit(X_train[y_train == 0])

    # 攻击分类
    attack_clf, attack_le = train_attack_classifier_v2(dataset)

    # 可视化
    print("\n[可视化] 生成图表...")
    plot_roc_curves(results, y_test)
    plot_confusion_matrices(results, y_test)
    plot_feature_importance(ensemble, feature_names)
    plot_model_comparison(results)

    # 保存
    save_models_v2(ensemble, iso, attack_clf, attack_le, feature_names)

    # 推理演示
    print("\n" + "=" * 60)
    print("推理演示")
    print("=" * 60)
    classifier = BehaviorClassifier.from_disk()

    # 正常
    normal_sample = dataset["normal_val"][0][0]
    r = classifier.classify(normal_sample)
    print(f"\n正常序列: anomaly={r['is_anomaly']}, conf={r['confidence']:.3f}, "
          f"normal_p={r['normal_prob']:.3f}, anomaly_p={r['anomaly_prob']:.3f}")

    # 攻击
    if dataset["attacks"]:
        attack_sample = dataset["attacks"][0][0]
        r = classifier.classify(attack_sample)
        print(f"攻击序列: anomaly={r['is_anomaly']}, conf={r['confidence']:.3f}, "
              f"type={r['anomaly_type']}, normal_p={r['normal_prob']:.3f}")

    # 滑动窗口
    if dataset["attacks"]:
        long_seq = dataset["attacks"][5][0]
        windows = classifier.classify_sliding_window(long_seq, window_size=100, step=50)
        anomaly_windows = [w for w in windows if w["is_anomaly"]]
        print(f"\n滑动窗口分析: {len(windows)} 窗口, {len(anomaly_windows)} 异常")

    print(f"\n✅ 训练完成！模型 → {MODEL_DIR}/")
    print(f"📊 图表 → {FIGURE_DIR}/")
    return classifier


if __name__ == "__main__":
    run_training()
