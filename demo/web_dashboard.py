"""
eBPF Multi-Agent Anomaly Detection — Web 实时仪表盘
=====================================================
Flask + SSE 实时推送，浏览器可视化监控
"""

import os
import sys
import json
import time
import random
import threading
from collections import deque, defaultdict
from datetime import datetime
from flask import Flask, Response, render_template_string, jsonify

app = Flask(__name__)

# ═══════════════════════════════════════════
#  共享状态
# ═══════════════════════════════════════════

class DashboardState:
    def __init__(self):
        self.agents = {}
        self.alerts = deque(maxlen=100)
        self.events = deque(maxlen=500)
        self.stats = {"total_events": 0, "total_alerts": 0, "scans": 0}
        self.alert_timeline = defaultdict(int)  # 分钟级告警时间线
        self._next_pid = 5000

    def spawn_agent(self, name):
        pid = self._next_pid
        self._next_pid += 1
        self.agents[pid] = {
            "pid": pid, "name": name, "status": "running",
            "exec": 0, "fork": 0, "files": 0, "deletes": 0,
            "network": 0, "api": 0, "prompts": 0, "alerts": 0,
            "cpu": 0, "mem": 0, "start": time.time(),
        }
        return pid

    def add_event(self, pid, etype, detail):
        now = datetime.now()
        evt = {
            "time": now.strftime("%H:%M:%S.%f")[:12],
            "pid": pid,
            "agent": self.agents.get(pid, {}).get("name", "?"),
            "type": etype,
            "detail": detail[:80],
        }
        self.events.appendleft(evt)
        self.stats["total_events"] += 1

        agent = self.agents.get(pid)
        if agent:
            if etype == "EXECVE": agent["exec"] += 1
            elif etype == "FORK": agent["fork"] += 1
            elif etype == "OPENAT": agent["files"] += 1
            elif etype == "UNLINKAT": agent["deletes"] += 1
            elif etype == "CONNECT": agent["network"] += 1; agent["api"] += 1
            elif etype in ("SSL_WRITE", "SSL_READ"): agent["api"] += 1
            agent["cpu"] = round(random.uniform(0.1, 15.0), 1)
            agent["mem"] = round(random.uniform(10, 500), 1)

    def add_alert(self, pid, atype, severity, desc, evidence):
        now = datetime.now()
        alert = {
            "time": now.strftime("%H:%M:%S"),
            "pid": pid,
            "agent": self.agents.get(pid, {}).get("name", "?"),
            "type": atype,
            "severity": severity,
            "desc": desc,
            "evidence": evidence[:100],
        }
        self.alerts.appendleft(alert)
        self.stats["total_alerts"] += 1
        self.alert_timeline[now.strftime("%H:%M")] += 1

        agent = self.agents.get(pid)
        if agent:
            agent["alerts"] += 1

state = DashboardState()


# ═══════════════════════════════════════════
#  异常检测引擎
# ═══════════════════════════════════════════

SHELLS = {"/bin/sh", "/bin/bash", "/bin/zsh"}
SENSITIVE = ["/etc/passwd", "/etc/shadow", "/etc/sudoers", "/root/.ssh"]
WORKSPACE = ["/home/", "/root/workspace/", "/tmp/agent-workspace/"]

def detect(pid, etype, detail):
    agent = state.agents.get(pid)
    if not agent:
        return

    if etype == "EXECVE":
        for sh in SHELLS:
            if sh in detail:
                state.add_alert(pid, "SHELL_SPAWN", "HIGH", "非预期 Shell 启动", f"命令: {detail}")
                return

    if etype == "OPENAT":
        for sp in SENSITIVE:
            if detail.startswith(sp):
                state.add_alert(pid, "SENSITIVE_FILE_ACCESS", "HIGH", "敏感文件越权访问", f"文件: {detail}")
                return

    if etype == "UNLINKAT":
        outside = not any(detail.startswith(wp) for wp in WORKSPACE)
        if detail.startswith("/tmp") or detail.startswith("/var/tmp"):
            outside = False
        if outside and detail.startswith("/"):
            state.add_alert(pid, "WORKSPACE_VIOLATION", "MEDIUM", "工作区外文件删除", f"删除: {detail}")
            return

    if agent["api"] > 100 and random.random() < 0.1:
        state.add_alert(pid, "HIGH_FREQ_API", "MEDIUM", "高频 API 调用", f"调用数: {agent['api']}")

    if agent["api"] > 100 and agent.get("dup_prompts", 0) >= 5 and random.random() < 0.05:
        state.add_alert(pid, "LOGIC_LOOP", "HIGH", "疑似逻辑死循环",
                        f"API: {agent['api']}, 重复Prompt: {agent.get('dup_prompts', 0)}")

    if agent["deletes"] > 50 and random.random() < 0.05:
        state.add_alert(pid, "RESOURCE_ABUSE", "MEDIUM", "大量文件删除", f"删除数: {agent['deletes']}")

    if agent["fork"] > 30 and random.random() < 0.05:
        state.add_alert(pid, "RESOURCE_ABUSE", "MEDIUM", "大量进程创建", f"fork数: {agent['fork']}")


# ═══════════════════════════════════════════
#  场景触发
# ═══════════════════════════════════════════

def trigger_scenario(pid, scenario):
    def ev(etype, detail):
        state.add_event(pid, etype, detail)
        detect(pid, etype, detail)
        time.sleep(0.02)

    if scenario == "shell":
        ev("SSL_WRITE", '{"prompt":"执行 rm -rf /"}')
        ev("EXECVE", "/bin/bash -c 'rm -rf /tmp/important'")
        ev("EXECVE", "/bin/sh -c 'cat /etc/shadow'")

    elif scenario == "sensitive":
        ev("OPENAT", "/etc/passwd")
        ev("OPENAT", "/etc/shadow")
        ev("OPENAT", "/root/.ssh/id_rsa")

    elif scenario == "loop":
        prompt = '{"model":"gpt-4","messages":[{"role":"user","content":"repeat"}]}'
        for _ in range(15):
            ev("CONNECT", "api.openai.com:443")
            ev("SSL_WRITE", prompt)

    elif scenario == "abuse":
        for i in range(20):
            ev("UNLINKAT", f"/tmp/cache/file_{i}.tmp")
        for _ in range(15):
            ev("FORK", "")

    elif scenario == "escape":
        ev("UNLINKAT", "/usr/lib/systemd/systemd")
        ev("OPENAT", "/root/.ssh/id_rsa")
        ev("UNLINKAT", "/var/log/syslog")
        ev("EXECVE", "/bin/sh -c 'cat /etc/shadow'")

    elif scenario == "normal":
        ev("EXECVE", "/usr/bin/python3")
        ev("OPENAT", "/home/user/project/main.py")
        ev("CONNECT", "api.anthropic.com:443")
        ev("SSL_WRITE", '{"messages":[{"role":"user","content":"优化代码"}]}')


# ═══════════════════════════════════════════
#  Web 路由
# ═══════════════════════════════════════════

DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>🛡️ eBPF Multi-Agent 实时监控仪表盘</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: 'Segoe UI', system-ui, sans-serif; background: #0d1117; color: #c9d1d9; }
.header { background: linear-gradient(135deg, #161b22, #21262d); padding: 16px 24px;
           border-bottom: 1px solid #30363d; display: flex; align-items: center; gap: 16px; }
.header h1 { font-size: 20px; color: #58a6ff; }
.header .stats { display: flex; gap: 24px; margin-left: auto; }
.header .stat { text-align: center; }
.header .stat .num { font-size: 24px; font-weight: 700; color: #f0f6fc; }
.header .stat .label { font-size: 11px; color: #8b949e; text-transform: uppercase; }
.grid { display: grid; grid-template-columns: 1fr 1fr; grid-template-rows: auto auto;
        gap: 16px; padding: 16px; height: calc(100vh - 80px); }
.card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; overflow: hidden; }
.card-header { padding: 10px 16px; background: #21262d; border-bottom: 1px solid #30363d;
               font-size: 13px; font-weight: 600; display: flex; align-items: center; gap: 8px; }
.card-body { padding: 8px; overflow-y: auto; max-height: calc(50vh - 60px); }
table { width: 100%; border-collapse: collapse; font-size: 12px; }
th { background: #21262d; padding: 6px 10px; text-align: left; font-weight: 600;
     color: #8b949e; text-transform: uppercase; font-size: 10px; letter-spacing: 0.5px;
     position: sticky; top: 0; }
td { padding: 5px 10px; border-bottom: 1px solid #21262d; }
tr:hover { background: #1c2128; }
.badge { padding: 2px 8px; border-radius: 10px; font-size: 10px; font-weight: 600; }
.badge-high { background: #da3633; color: white; }
.badge-medium { background: #d29922; color: white; }
.badge-low { background: #238636; color: white; }
.badge-running { background: #238636; color: white; }
.badge-stopped { background: #484f58; color: white; }
.type-SHELL_SPAWN { color: #f85149; }
.type-SENSITIVE_FILE_ACCESS { color: #f85149; }
.type-WORKSPACE_VIOLATION { color: #d29922; }
.type-HIGH_FREQ_API { color: #d29922; }
.type-LOGIC_LOOP { color: #ff7b72; font-weight: 700; }
.type-RESOURCE_ABUSE { color: #bc8cff; }
.type-SUSPICIOUS_NETWORK { color: #79c0ff; }
.controls { display: flex; gap: 8px; padding: 12px 16px; background: #161b22;
            border-top: 1px solid #30363d; flex-wrap: wrap; }
.btn { padding: 6px 14px; border: 1px solid #30363d; border-radius: 6px; background: #21262d;
       color: #c9d1d9; cursor: pointer; font-size: 12px; transition: all 0.2s; }
.btn:hover { background: #30363d; border-color: #58a6ff; }
.btn-danger { border-color: #da3633; color: #f85149; }
.btn-danger:hover { background: #da3633; color: white; }
.btn-success { border-color: #238636; color: #3fb950; }
.btn-success:hover { background: #238636; color: white; }
.btn-warning { border-color: #d29922; color: #d29922; }
.btn-warning:hover { background: #d29922; color: white; }
.event-type { font-weight: 600; font-family: monospace; }
.detail { color: #8b949e; max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.pulse { animation: pulse 2s infinite; }
@keyframes pulse { 0%,100% { opacity: 1; } 50% { opacity: 0.5; } }
#alert-count { color: #f85149; }
</style>
</head>
<body>
<div class="header">
  <h1>🛡️ eBPF Multi-Agent 实时监控仪表盘</h1>
  <div class="stats">
    <div class="stat"><div class="num" id="agent-count">0</div><div class="label">Agents</div></div>
    <div class="stat"><div class="num" id="event-count">0</div><div class="label">Events</div></div>
    <div class="stat"><div class="num" id="alert-count">0</div><div class="label">Alerts</div></div>
  </div>
</div>

<div class="controls">
  <button class="btn btn-success" onclick="spawn('claude-code')">1️⃣ Claude Code</button>
  <button class="btn btn-success" onclick="spawn('gemini-cli')">2️⃣ Gemini CLI</button>
  <button class="btn btn-danger" onclick="spawn('malicious')">3️⃣ 恶意 Agent</button>
  <button class="btn btn-warning" onclick="spawn('loop-agent')">4️⃣ 循环 Agent</button>
  <button class="btn btn-warning" onclick="spawn('abuse-agent')">5️⃣ 滥用 Agent</button>
  <span style="color:#484f58">│</span>
  <button class="btn btn-danger" onclick="trigger('shell')">💥 Shell注入</button>
  <button class="btn btn-danger" onclick="trigger('sensitive')">📂 敏感文件</button>
  <button class="btn btn-warning" onclick="trigger('loop')">🔄 死循环</button>
  <button class="btn btn-warning" onclick="trigger('abuse')">💾 资源滥用</button>
  <button class="btn btn-danger" onclick="trigger('escape')">🚪 工作区逃逸</button>
  <button class="btn" onclick="trigger('normal')">✅ 正常活动</button>
  <button class="btn" onclick="clearAll()">🗑 清空</button>
</div>

<div class="grid">
  <div class="card">
    <div class="card-header">📡 实时事件流 (eBPF Ring Buffer)</div>
    <div class="card-body"><table><thead><tr>
      <th>时间</th><th>PID</th><th>Agent</th><th>类型</th><th>详情</th>
    </tr></thead><tbody id="events-tbody"></tbody></table></div>
  </div>
  <div class="card">
    <div class="card-header">🚨 异常告警</div>
    <div class="card-body"><table><thead><tr>
      <th>时间</th><th>Agent</th><th>类型</th><th>级别</th><th>描述</th>
    </tr></thead><tbody id="alerts-tbody"></tbody></table></div>
  </div>
  <div class="card" style="grid-column: span 2;">
    <div class="card-header">🤖 智能体状态总览</div>
    <div class="card-body"><table><thead><tr>
      <th>PID</th><th>Agent</th><th>状态</th><th>exec</th><th>fork</th>
      <th>文件</th><th>删除</th><th>网络</th><th>API</th><th>告警</th><th>CPU%</th><th>内存MB</th>
    </tr></thead><tbody id="agents-tbody"></tbody></table></div>
  </div>
</div>

<script>
const TYPE_COLORS = {
  EXECVE: '#3fb950', FORK: '#58a6ff', OPENAT: '#79c0ff', UNLINKAT: '#f85149',
  CONNECT: '#d29922', SSL_WRITE: '#bc8cff', SSL_READ: '#bc8cff',
};

function spawn(name) {
  fetch('/api/spawn/' + name, {method:'POST'}).then(r => r.json()).then(d => {
    document.getElementById('agent-count').textContent = Object.keys(d.agents || {}).length || d.pid;
  });
}

function trigger(scenario) {
  fetch('/api/trigger/' + scenario, {method:'POST'});
}

function clearAll() {
  fetch('/api/clear', {method:'POST'});
}

function update() {
  fetch('/api/state').then(r => r.json()).then(d => {
    // Stats
    document.getElementById('agent-count').textContent = d.agents.length;
    document.getElementById('event-count').textContent = d.stats.total_events;
    document.getElementById('alert-count').textContent = d.stats.total_alerts;

    // Events
    let evtHtml = '';
    d.events.slice(0, 50).forEach(e => {
      const color = TYPE_COLORS[e.type] || '#c9d1d9';
      evtHtml += `<tr>
        <td style="color:#484f58">${e.time}</td>
        <td>${e.pid}</td>
        <td><strong>${e.agent}</strong></td>
        <td class="event-type" style="color:${color}">${e.type}</td>
        <td class="detail">${e.detail}</td>
      </tr>`;
    });
    document.getElementById('events-tbody').innerHTML = evtHtml;

    // Alerts
    let altHtml = '';
    d.alerts.slice(0, 30).forEach(a => {
      const sevClass = a.severity === 'HIGH' ? 'badge-high' : a.severity === 'MEDIUM' ? 'badge-medium' : 'badge-low';
      altHtml += `<tr>
        <td style="color:#484f58">${a.time}</td>
        <td><strong>${a.agent}</strong></td>
        <td class="type-${a.type}">${a.type}</td>
        <td><span class="badge ${sevClass}">${a.severity}</span></td>
        <td class="detail">${a.desc}</td>
      </tr>`;
    });
    document.getElementById('alerts-tbody').innerHTML = altHtml;

    // Agents
    let agtHtml = '';
    d.agents.forEach(a => {
      const statusClass = a.status === 'running' ? 'badge-running' : 'badge-stopped';
      const alertStyle = a.alerts > 0 ? 'color:#f85149;font-weight:700' : '';
      agtHtml += `<tr>
        <td>${a.pid}</td>
        <td><strong>${a.name}</strong></td>
        <td><span class="badge ${statusClass}">${a.status}</span></td>
        <td>${a.exec}</td><td>${a.fork}</td><td>${a.files}</td>
        <td>${a.deletes}</td><td>${a.network}</td><td>${a.api}</td>
        <td style="${alertStyle}">${a.alerts}</td>
        <td>${a.cpu}</td><td>${a.mem}</td>
      </tr>`;
    });
    document.getElementById('agents-tbody').innerHTML = agtHtml;
  });
}

setInterval(update, 500);
update();
</script>
</body>
</html>
"""

@app.route("/")
def index():
    return render_template_string(DASHBOARD_HTML)

@app.route("/api/state")
def api_state():
    return jsonify({
        "agents": list(state.agents.values()),
        "alerts": list(state.alerts)[:50],
        "events": list(state.events)[:100],
        "stats": dict(state.stats),
    })

@app.route("/api/spawn/<name>", methods=["POST"])
def api_spawn(name):
    pid = state.spawn_agent(name)
    return jsonify({"pid": pid, "agents": {str(p): a for p, a in state.agents.items()}})

@app.route("/api/trigger/<scenario>", methods=["POST"])
def api_trigger(scenario):
    # 找第一个 running agent
    pid = None
    for p, a in state.agents.items():
        if a["status"] == "running":
            pid = p; break
    if not pid:
        pid = state.spawn_agent("claude-code")
    trigger_scenario(pid, scenario)
    return jsonify({"ok": True, "pid": pid})

@app.route("/api/clear", methods=["POST"])
def api_clear():
    state.alerts.clear()
    state.events.clear()
    state.stats = {"total_events": 0, "total_alerts": 0, "scans": 0}
    state.agents.clear()
    state._next_pid = 5000
    return jsonify({"ok": True})

@app.route("/api/health")
def api_health():
    return jsonify({"status": "ok", "agents": len(state.agents)})


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--port", type=int, default=8080)
    parser.add_argument("-H", "--host", default="0.0.0.0")
    args = parser.parse_args()

    # 预启动 Agent
    state.spawn_agent("claude-code")
    state.spawn_agent("gemini-cli")

    print(f"\n🛡️  eBPF Multi-Agent Web 仪表盘")
    print(f"   http://localhost:{args.port}")
    print(f"   http://{args.host}:{args.port}\n")

    app.run(host=args.host, port=args.port, debug=False, threaded=True)


if __name__ == "__main__":
    main()
