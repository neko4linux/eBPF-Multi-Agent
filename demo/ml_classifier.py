"""
eBPF Multi-Agent Anomaly Detection — 机器学习行为分类模块
==========================================================
基于 ADFA-LD 数据集训练，识别系统调用异常模式
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
    VotingClassifier, IsolationForest,
)
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.neural_network import MLPClassifier
from sklearn.model_selection import (
    StratifiedKFold, cross_val_score, train_test_split,
)
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import (
    classification_report, confusion_matrix,
    accuracy_score, f1_score, roc_auc_score,
)
from sklearn.pipeline import Pipeline


# ═══════════════════════════════════════════
#  常量定义
# ═══════════════════════════════════════════

DATA_DIR = Path(__file__).parent / "data" / "ADFA-LD"
MODEL_DIR = Path(__file__).parent / "models"
MODEL_DIR.mkdir(exist_ok=True)

# 攻击类型映射
ATTACK_TYPES = {
    "Adduser":          "SHELL_SPAWN",       # 添加用户 → Shell类攻击
    "Hydra_FTP":        "HIGH_FREQ_API",     # FTP暴力破解 → 高频API
    "Hydra_SSH":        "HIGH_FREQ_API",     # SSH暴力破解 → 高频API
    "Java_Meterpreter": "SUSPICIOUS_NETWORK", # Meterpreter → 可疑网络
    "Meterpreter":      "SUSPICIOUS_NETWORK",
    "Web_Shell":        "SHELL_SPAWN",       # WebShell → Shell类
}

# 关键系统调用 (x86-64) 映射
SYSCALL_MAP = {
    0: "read", 1: "write", 2: "open", 3: "close",
    4: "stat", 5: "fstat", 6: "lstat", 7: "poll",
    8: "lseek", 9: "mmap", 10: "mprotect", 11: "munmap",
    12: "brk", 13: "rt_sigaction", 14: "rt_sigprocmask",
    16: "ioctl", 17: "pread64", 19: "readv",
    20: "writev", 21: "access", 22: "pipe",
    24: "sched_yield", 32: "dup", 33: "dup2",
    35: "nanosleep", 39: "getpid", 41: "socket",
    42: "connect", 43: "accept", 44: "sendto",
    45: "recvfrom", 46: "sendmsg", 47: "recvmsg",
    49: "bind", 50: "listen", 56: "clone",
    57: "fork", 58: "vfork", 59: "execve",
    60: "exit", 61: "wait4", 62: "kill",
    63: "uname", 72: "fcntl", 78: "getdents",
    79: "getcwd", 80: "chdir", 82: "rename",
    83: "mkdir", 84: "rmdir", 87: "unlink",
    89: "readlink", 90: "chmod", 92: "chown",
    95: "umask", 99: "sysinfo", 102: "getuid",
    104: "getgid", 107: "geteuid", 108: "getegid",
    158: "arch_prctl", 217: "getdents64",
    231: "exit_group", 257: "openat", 262: "newfstatat",
    263: "unlinkat", 288: "accept4", 292: "dup3",
    302: "prlimit64", 318: "getrandom",
}

# 特征工程的 n-gram 大小
N_GRAM_SIZES = [2, 3, 5]


# ═══════════════════════════════════════════
#  数据加载
# ═══════════════════════════════════════════

def load_syscall_sequences(directory: Path, label: int) -> list:
    """加载目录中所有系统调用序列文件"""
    sequences = []
    if not directory.exists():
        return sequences
    for f in sorted(directory.glob("*.txt")):
        try:
            nums = [int(x) for x in f.read_text().strip().split() if x.isdigit()]
            if len(nums) > 5:  # 过滤太短的序列
                sequences.append((nums, label, f.name))
        except (ValueError, OSError):
            continue
    return sequences


def load_adfa_dataset() -> dict:
    """加载完整 ADFA-LD 数据集"""
    print("[数据] 加载 ADFA-LD 数据集...")

    # 正常样本
    normal_train = load_syscall_sequences(DATA_DIR / "Training_Data_Master", 0)
    normal_val = load_syscall_sequences(DATA_DIR / "Validation_Data_Master", 0)

    # 攻击样本
    attack_all = []
    attack_dir = DATA_DIR / "Attack_Data_Master"
    if attack_dir.exists():
        for attack_type_dir in sorted(attack_dir.iterdir()):
            if attack_type_dir.is_dir():
                attack_name = attack_type_dir.name
                # 提取攻击类别 (去掉数字后缀)
                base_name = attack_name.rstrip("0123456789").rstrip("_")
                seqs = load_syscall_sequences(attack_type_dir, 1)
                for seq, label, fname in seqs:
                    attack_all.append((seq, label, fname, base_name))

    dataset = {
        "normal_train": normal_train,
        "normal_val": normal_val,
        "attacks": attack_all,
        "total_normal": len(normal_train) + len(normal_val),
        "total_attack": len(attack_all),
    }

    print(f"  正常样本: 训练={len(normal_train)}, 验证={len(normal_val)}")
    print(f"  攻击样本: {len(attack_all)}")
    attack_types = Counter(a[3] for a in attack_all)
    for atype, count in attack_types.most_common():
        print(f"    {atype}: {count}")

    return dataset


# ═══════════════════════════════════════════
#  特征工程
# ═══════════════════════════════════════════

def extract_ngram_features(sequences: list, ngram_sizes: list = N_GRAM_SIZES,
                           top_k: int = 100) -> tuple:
    """
    从系统调用序列中提取 n-gram 频率特征
    
    核心思想:
    - 正常进程的系统调用模式相对固定
    - 攻击进程会引入异常的调用组合
    - n-gram 捕获调用之间的上下文关系
    """
    # 1) 收集所有 n-gram
    all_ngrams = set()
    seq_ngram_counts = []

    for seq, label, *rest in sequences:
        counts = {}
        for n in ngram_sizes:
            for i in range(len(seq) - n + 1):
                ng = tuple(seq[i:i + n])
                counts[ng] = counts.get(ng, 0) + 1
        seq_ngram_counts.append(counts)
        all_ngrams.update(counts.keys())

    # 2) 选择最频繁的 top_k 个 n-gram 作为特征
    global_counts = Counter()
    for counts in seq_ngram_counts:
        global_counts.update(counts)

    top_ngrams = [ng for ng, _ in global_counts.most_common(top_k)]

    # 3) 构建特征矩阵
    X = np.zeros((len(sequences), top_k), dtype=np.float32)
    for i, counts in enumerate(seq_ngram_counts):
        seq_len = len(sequences[i][0]) or 1
        for j, ng in enumerate(top_ngrams):
            X[i, j] = counts.get(ng, 0) / seq_len  # 归一化频率

    return X, top_ngrams


def extract_statistical_features(sequences: list) -> np.ndarray:
    """
    提取统计特征:
    - 序列长度
    - 唯一系统调用数量
    - 熵
    - 前N个系统调用的频率
    """
    n_features = 50  # 固定特征数
    X = np.zeros((len(sequences), n_features), dtype=np.float32)

    for i, (seq, label, *rest) in enumerate(sequences):
        if not seq:
            continue

        # 基本统计
        X[i, 0] = len(seq)                          # 序列长度
        X[i, 1] = len(set(seq))                      # 唯一调用数
        X[i, 2] = len(set(seq)) / max(len(seq), 1)   # 唯一率

        # 熵
        freq = Counter(seq)
        total = len(seq)
        entropy = -sum((c / total) * np.log2(c / total) for c in freq.values())
        X[i, 3] = entropy

        # 系统调用频率分布 (取 top 46 个常见 syscall)
        common_calls = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,
                        16,19,20,21,24,32,35,39,41,42,43,44,
                        45,46,47,49,50,56,57,59,60,61,63,72,
                        79,80,87,90,102,257,263,302]
        for j, sc in enumerate(common_calls[:46]):
            if j + 4 < n_features:
                X[i, j + 4] = freq.get(sc, 0) / total

    return X


def build_features(sequences: list) -> tuple:
    """组合所有特征"""
    X_ngram, ngram_names = extract_ngram_features(sequences)
    X_stat = extract_statistical_features(sequences)
    X = np.hstack([X_ngram, X_stat])
    y = np.array([s[1] for s in sequences])
    return X, y, ngram_names


# ═══════════════════════════════════════════
#  模型训练
# ═══════════════════════════════════════════

def train_models(X_train, y_train, X_test, y_test) -> dict:
    """训练多个模型并比较性能"""
    print("\n[训练] 训练多个分类器...")

    models = {
        "RandomForest": RandomForestClassifier(
            n_estimators=200, max_depth=15, min_samples_split=5,
            class_weight="balanced", random_state=42, n_jobs=-1,
        ),
        "GradientBoosting": GradientBoostingClassifier(
            n_estimators=150, max_depth=6, learning_rate=0.1,
            random_state=42,
        ),
        "LogisticRegression": Pipeline([
            ("scaler", StandardScaler()),
            ("clf", LogisticRegression(
                max_iter=1000, class_weight="balanced", random_state=42,
            )),
        ]),
        "MLP": Pipeline([
            ("scaler", StandardScaler()),
            ("clf", MLPClassifier(
                hidden_layer_sizes=(128, 64, 32), max_iter=300,
                early_stopping=True, random_state=42,
            )),
        ]),
    }

    results = {}

    for name, model in models.items():
        print(f"  训练 {name}...", end=" ")
        t0 = time.time()

        # 训练
        model.fit(X_train, y_train)

        # 预测
        y_pred = model.predict(X_test)
        y_proba = None
        if hasattr(model, "predict_proba"):
            y_proba = model.predict_proba(X_test)[:, 1]
        elif hasattr(model, "decision_function"):
            y_proba = model.decision_function(X_test)

        # 评估
        acc = accuracy_score(y_test, y_pred)
        f1 = f1_score(y_test, y_pred, average="weighted")
        auc = roc_auc_score(y_test, y_proba) if y_proba is not None else 0

        elapsed = time.time() - t0

        results[name] = {
            "model": model,
            "accuracy": acc,
            "f1": f1,
            "auc": auc,
            "time": elapsed,
            "y_pred": y_pred,
        }

        print(f"Acc={acc:.4f}  F1={f1:.4f}  AUC={auc:.4f}  ({elapsed:.1f}s)")

    return results


def build_ensemble(results: dict, X_train, y_train) -> Pipeline:
    """构建集成模型"""
    print("\n[训练] 构建 VotingClassifier 集成模型...")

    estimators = []
    for name in ["RandomForest", "GradientBoosting", "LogisticRegression"]:
        if name in results:
            estimators.append((name, results[name]["model"]))

    ensemble = VotingClassifier(
        estimators=estimators, voting="soft", n_jobs=-1,
    )
    ensemble.fit(X_train, y_train)
    return ensemble


def train_isolation_forest(X_train) -> IsolationForest:
    """训练无监督异常检测模型 (Isolation Forest)"""
    print("\n[训练] 训练 Isolation Forest (无监督异常检测)...")
    iso = IsolationForest(
        n_estimators=200, contamination=0.1,
        random_state=42, n_jobs=-1,
    )
    iso.fit(X_train)
    return iso


# ═══════════════════════════════════════════
#  攻击类型分类器
# ═══════════════════════════════════════════

def train_attack_classifier(dataset: dict) -> Pipeline:
    """训练攻击类型分类器 (多分类)"""
    print("\n[训练] 训练攻击类型分类器...")

    # 只用攻击样本
    attacks = dataset["attacks"]
    if len(attacks) < 10:
        print("  攻击样本不足，跳过")
        return None

    # 提取攻击类别
    labels = []
    valid_attacks = []
    for seq, label, fname, attack_type in attacks:
        if attack_type in ATTACK_TYPES:
            labels.append(ATTACK_TYPES[attack_type])
            valid_attacks.append((seq, 1, fname))

    if len(set(labels)) < 2:
        print("  攻击类型不足2种，跳过")
        return None

    # 添加正常样本
    normal = dataset["normal_train"][:200]
    for seq, label, fname in normal:
        valid_attacks.append((seq, 0, fname))
        labels.append("NORMAL")

    # 特征
    X, _, _ = build_features(valid_attacks)
    le = LabelEncoder()
    y = le.fit_transform(labels)

    # 训练
    clf = Pipeline([
        ("scaler", StandardScaler()),
        ("clf", RandomForestClassifier(
            n_estimators=200, max_depth=15,
            class_weight="balanced", random_state=42, n_jobs=-1,
        )),
    ])

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y,
    )
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    print(f"  攻击分类 Accuracy: {accuracy_score(y_test, y_pred):.4f}")
    print(f"  类别: {list(le.classes_)}")

    return clf, le


# ═══════════════════════════════════════════
#  评估与报告
# ═══════════════════════════════════════════

def evaluate_models(results: dict, y_test: np.ndarray, X_test: np.ndarray = None):
    """输出详细评估报告"""
    print("\n" + "=" * 60)
    print("模型评估报告")
    print("=" * 60)

    # 找最佳模型
    best_name = max(results, key=lambda k: results[k]["f1"])
    best = results[best_name]

    print(f"\n🏆 最佳模型: {best_name}")
    print(f"   Accuracy: {best['accuracy']:.4f}")
    print(f"   F1-Score: {best['f1']:.4f}")
    print(f"   AUC-ROC:  {best['auc']:.4f}")

    print(f"\n📊 {best_name} 分类报告:")
    print(classification_report(
        y_test, best["y_pred"],
        target_names=["Normal", "Anomaly"],
    ))

    print("混淆矩阵:")
    cm = confusion_matrix(y_test, best["y_pred"])
    print(f"  TN={cm[0,0]}  FP={cm[0,1]}")
    print(f"  FN={cm[1,0]}  TP={cm[1,1]}")

    # 交叉验证 (用最佳模型)
    if X_test is not None:
        print(f"\n📈 {best_name} 5-fold 交叉验证:")
        cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
        scores = cross_val_score(best["model"], X_test, y_test,
                                  cv=cv, scoring="f1_weighted", n_jobs=-1)
        print(f"   F1 per fold: {[f'{s:.4f}' for s in scores]}")
        print(f"   Mean F1: {scores.mean():.4f} ± {scores.std():.4f}")
    return best_name


# ═══════════════════════════════════════════
#  模型保存/加载
# ═══════════════════════════════════════════

def save_models(ensemble, iso_forest, attack_clf, attack_le, scaler, feature_names):
    """保存所有模型"""
    print(f"\n[保存] 模型保存到 {MODEL_DIR}/")
    joblib.dump(ensemble, MODEL_DIR / "ensemble.pkl")
    joblib.dump(iso_forest, MODEL_DIR / "isolation_forest.pkl")
    if attack_clf:
        joblib.dump(attack_clf, MODEL_DIR / "attack_classifier.pkl")
        joblib.dump(attack_le, MODEL_DIR / "attack_label_encoder.pkl")
    joblib.dump(scaler, MODEL_DIR / "scaler.pkl")
    joblib.dump(feature_names, MODEL_DIR / "feature_names.json")
    print("  ✅ 所有模型已保存")


def load_models() -> dict:
    """加载已训练的模型"""
    models = {}
    for name, fname in [
        ("ensemble", "ensemble.pkl"),
        ("isolation_forest", "isolation_forest.pkl"),
        ("attack_classifier", "attack_classifier.pkl"),
        ("attack_label_encoder", "attack_label_encoder.pkl"),
        ("scaler", "scaler.pkl"),
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
    """
    实时行为分类器
    输入: 系统调用序列
    输出: 正常/异常 + 异常类型 + 置信度
    """

    def __init__(self, models: dict = None):
        self.models = models or {}
        self.ready = bool(self.models.get("ensemble"))

    @classmethod
    def from_disk(cls):
        """从磁盘加载模型"""
        models = load_models()
        return cls(models)

    def classify(self, syscall_seq: list) -> dict:
        """
        分类单个系统调用序列
        
        返回:
        {
            "is_anomaly": bool,
            "confidence": float,
            "anomaly_type": str,
            "details": str,
        }
        """
        if not self.ready:
            return {"is_anomaly": None, "confidence": 0, "error": "模型未加载"}

        # 构建特征
        seq_data = [(syscall_seq, 0, "live")]
        X, _, _ = build_features(seq_data)

        # 1) 有监督分类 (集成模型)
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
            "details": "",
        }

        # 2) Isolation Forest 无监督验证
        if "isolation_forest" in self.models:
            iso = self.models["isolation_forest"]
            iso_pred = iso.predict(X)[0]  # 1=normal, -1=anomaly
            iso_score = iso.decision_function(X)[0]
            result["iso_anomaly"] = bool(iso_pred == -1)
            result["iso_score"] = float(iso_score)

        # 3) 攻击类型分类
        if is_anomaly and "attack_classifier" in self.models:
            atk_clf = self.models["attack_classifier"]
            atk_le = self.models["attack_label_encoder"]
            atk_pred = atk_clf.predict(X)[0]
            atk_proba = atk_clf.predict_proba(X)[0]
            result["anomaly_type"] = atk_le.inverse_transform([atk_pred])[0]
            result["type_confidence"] = float(max(atk_proba))

        return result

    def classify_sliding_window(self, syscall_seq: list, window_size: int = 200,
                                 step: int = 50) -> list:
        """滑动窗口分类 — 检测序列中的异常段"""
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
    """完整训练流程"""
    print("╔══════════════════════════════════════════════════════╗")
    print("║  eBPF Multi-Agent ML 行为分类器训练                  ║")
    print("║  数据集: ADFA-LD (Linux System Call Intrusion)       ║")
    print("╚══════════════════════════════════════════════════════╝\n")

    # 1. 加载数据
    dataset = load_adfa_dataset()

    # 2. 构建二分类数据集 (正常 vs 异常)
    all_normal = dataset["normal_train"] + dataset["normal_val"]
    all_attacks = [(s, l, f) for s, l, f, _ in dataset["attacks"]]

    print(f"\n[特征] 构建特征矩阵...")
    print(f"  正常: {len(all_normal)}, 攻击: {len(all_attacks)}")

    # 平衡采样
    n_normal = min(len(all_normal), 1500)
    n_attack = min(len(all_attacks), 1500)
    balanced = all_normal[:n_normal] + all_attacks[:n_attack]

    X, y, feature_names = build_features(balanced)
    print(f"  特征维度: {X.shape}")
    print(f"  标签分布: Normal={sum(y==0)}, Anomaly={sum(y==1)}")

    # 3. 划分数据集
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y,
    )
    print(f"  训练集: {X_train.shape[0]}, 测试集: {X_test.shape[0]}")

    # 4. 训练模型
    results = train_models(X_train, y_train, X_test, y_test)

    # 5. 评估
    best_name = evaluate_models(results, y_test, X_test)

    # 6. 集成模型
    ensemble = build_ensemble(results, X_train, y_train)
    y_pred_ens = ensemble.predict(X_test)
    print(f"\n[集成] Ensemble Accuracy: {accuracy_score(y_test, y_pred_ens):.4f}")

    # 7. Isolation Forest
    iso_forest = train_isolation_forest(X_train[y_train == 0])  # 只用正常数据训练

    # 8. 攻击类型分类器
    attack_result = train_attack_classifier(dataset)
    attack_clf, attack_le = None, None
    if attack_result:
        attack_clf, attack_le = attack_result

    # 9. 保存
    scaler = StandardScaler().fit(X_train)
    save_models(ensemble, iso_forest, attack_clf, attack_le, scaler, feature_names)

    # 10. 演示推理
    print("\n" + "=" * 60)
    print("推理演示")
    print("=" * 60)

    classifier = BehaviorClassifier.from_disk()

    # 测试正常序列
    normal_sample = dataset["normal_val"][0][0]
    r = classifier.classify(normal_sample)
    print(f"\n正常序列: anomaly={r['is_anomaly']}, conf={r['confidence']:.3f}")

    # 测试攻击序列
    if dataset["attacks"]:
        attack_sample = dataset["attacks"][0][0]
        r = classifier.classify(attack_sample)
        print(f"攻击序列: anomaly={r['is_anomaly']}, conf={r['confidence']:.3f}, type={r['anomaly_type']}")

    print("\n✅ 训练完成！模型已保存到 models/ 目录")
    return classifier


if __name__ == "__main__":
    run_training()
