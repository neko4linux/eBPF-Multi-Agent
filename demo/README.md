# eBPF Multi-Agent Anomaly Detection — Demo & Sandbox

## 赛题

**2026年全国大学生计算机系统能力大赛 - OS功能挑战赛道**
基于 eBPF 的系统级多智能体异常监测框架与方法

## 快速开始

```bash
cd ~/eBPF-Multi-Agent/demo

# 1. 训练 ML 模型
uv run python ml_classifier_v2.py

# 2. 启动交互式沙箱 (推荐)
uv run python sandbox_cli.py

# 3. 运行完整 demo
uv run python main_with_ml.py

# 4. 实时进程监控
uv run python live_monitor.py -d 30

# 5. TUI 沙箱 (需要终端支持)
uv run python sandbox.py
```

## 沙箱命令

```
sandbox> help                    # 查看所有命令
sandbox> spawn claude-code       # 启动正常 Agent
sandbox> spawn malicious         # 启动恶意 Agent
sandbox> spawn loop-agent        # 启动循环 Agent
sandbox> shell 5003              # 对 PID=5003 触发 Shell 注入
sandbox> sensitive 5003          # 触发敏感文件访问
sandbox> loop 5004               # 触发逻辑死循环
sandbox> abuse 5005              # 触发资源滥用
sandbox> escape 5003             # 触发工作区逃逸
sandbox> status                  # 查看 Agent 状态
sandbox> alerts                  # 查看告警
sandbox> auto                    # 自动运行模式
sandbox> demo                    # 一键运行全部场景
sandbox> q                       # 退出
```

## ML 模型性能

| 模型 | Accuracy | F1 | AUC |
|------|----------|-----|-----|
| RandomForest | 94.6% | 94.5% | 97.8% |
| Ensemble | 94.4% | - | 97.7% |
| 攻击分类 (4类) | 83.8% | - | - |

特征: 2715维 (n-gram + Markov转移矩阵 + 统计 + 转移熵)
数据集: ADFA-LD (5205正常 + 746攻击)

## 项目结构

```
demo/
├── sandbox_cli.py         # CLI 交互式沙箱 ⭐
├── sandbox.py             # TUI 沙箱 (textual)
├── main_with_ml.py        # 完整 demo (规则 + ML)
├── ml_classifier_v2.py    # ML 训练脚本
├── live_monitor.py        # 实时进程监控
├── main.py                # 基础 demo
├── common.py              # 数据结构
├── data/ADFA-LD/          # 数据集
├── models/                # 训练好的模型
└── figures/               # 可视化图表
```
