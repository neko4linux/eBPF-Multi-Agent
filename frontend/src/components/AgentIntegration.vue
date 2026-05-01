<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { useApi } from '../composables/useApi'
import type { AgentProfile, DetectedAgent, AnomalyRule, AgentTypeInfo } from '../composables/useApi'

const api = useApi()
const profiles = ref<AgentProfile[]>([])
const detected = ref<DetectedAgent[]>([])
const rules = ref<AnomalyRule[]>([])
const agentTypes = ref<AgentTypeInfo[]>([])
const selectedProfile = ref<AgentProfile | null>(null)
const simulating = ref(false)

const agentIcons: Record<string, string> = {
  'claude-code': '🟣',
  'codex': '🟢',
  'gemini-cli': '🔵',
  'kiro-cli': '🟠',
  'cursor': '🟡',
  'copilot': '⚫',
  'aider': '⚪',
  'continue': '🟤',
  'generic': '⬜',
}

const riskColors: Record<string, string> = {
  'LOW': 'var(--color-success, #3fb950)',
  'MEDIUM': 'var(--color-warning, #d29922)',
  'HIGH': 'var(--color-danger, #d29922)',
  'CRITICAL': 'var(--color-critical, #f85149)',
}

const sortedProfiles = computed(() => {
  return [...profiles.value].sort((a, b) => {
    const order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
    return order.indexOf(a.risk_level) - order.indexOf(b.risk_level)
  })
})

const activeAgents = computed(() => detected.value.filter(a => a.risk_score > 0.3))
const rulesByAgent = computed(() => {
  const map: Record<string, number> = {}
  for (const r of rules.value) {
    map[r.agent_type] = (map[r.agent_type] || 0) + 1
  }
  return map
})

async function loadProfiles() {
  try { profiles.value = await api.getAgentProfiles() } catch { /* ignore */ }
}

async function loadDetected() {
  try { detected.value = await api.getDetectedAgents() } catch { /* ignore */ }
}

async function loadRules() {
  try { rules.value = await api.getAnomalyRules() } catch { /* ignore */ }
}

async function loadAgentTypes() {
  try { agentTypes.value = await api.getAgentTypes() } catch { /* ignore */ }
}

// 模拟 Agent 检测
async function simulateDetection(type: string) {
  simulating.value = true
  try {
    await api.manualDetect({
      comm: type,
      cmdline: `${type} --interactive --model sonnet`,
      event_type: 'EXECVE',
      detail: `Simulated ${type} agent detection`,
    })
    // 刷新检测列表
    setTimeout(async () => {
      await loadDetected()
      simulating.value = false
    }, 500)
  } catch {
    simulating.value = false
  }
}

function riskPercent(score: number): number {
  return Math.min(Math.round(score * 100), 100)
}

onMounted(() => {
  loadProfiles()
  loadDetected()
  loadRules()
  loadAgentTypes()
})
</script>

<template>
  <div class="agent-integration">
    <header class="section-header">
      <h2>🤖 AI Agent 集成监控</h2>
      <p class="subtitle">实时检测和监控系统中运行的 AI 编程助手</p>
    </header>

    <!-- 概览统计 -->
    <div class="overview-grid">
      <div class="overview-card">
        <div class="ov-value">{{ profiles.length }}</div>
        <div class="ov-label">已注册 Agent 类型</div>
      </div>
      <div class="overview-card" :class="{ warning: activeAgents.length > 0 }">
        <div class="ov-value">{{ detected.length }}</div>
        <div class="ov-label">已检测到</div>
      </div>
      <div class="overview-card" :class="{ danger: activeAgents.length > 2 }">
        <div class="ov-value">{{ activeAgents.length }}</div>
        <div class="ov-label">高风险活跃</div>
      </div>
      <div class="overview-card">
        <div class="ov-value">{{ rules.length }}</div>
        <div class="ov-label">检测规则</div>
      </div>
    </div>

    <!-- 检测模拟器 -->
    <div class="card simulator">
      <div class="card-header">
        <span>🎯 检测模拟器</span>
        <span class="badge">演示模式</span>
      </div>
      <div class="sim-grid">
        <button
          v-for="t in agentTypes" :key="t.type"
          class="sim-btn" :class="[t.risk.toLowerCase(), { active: simulating }]"
          :disabled="simulating"
          @click="simulateDetection(t.type)"
        >
          <span class="sim-icon">{{ t.icon }}</span>
          <span class="sim-name">{{ t.name }}</span>
          <span class="sim-risk">{{ t.risk }}</span>
        </button>
      </div>
    </div>

    <!-- 已检测 Agent 列表 -->
    <div class="card" v-if="detected.length > 0">
      <div class="card-header">
        <span>🔍 已检测到的 Agent ({{ detected.length }})</span>
        <button class="btn-sm" @click="loadDetected()">🔄 刷新</button>
      </div>
      <div class="detected-list">
        <div v-for="agent in detected" :key="agent.pid" class="detected-item">
          <div class="det-left">
            <span class="det-icon">{{ agentIcons[agent.type] || '⬜' }}</span>
            <div class="det-info">
              <div class="det-name">{{ agent.profile?.name || agent.name }}</div>
              <div class="det-meta">PID: {{ agent.pid }} · {{ agent.type }}</div>
            </div>
          </div>
          <div class="det-center">
            <div class="risk-meter">
              <div class="risk-fill" :style="{ width: riskPercent(agent.risk_score) + '%' }"
                :class="{ low: agent.risk_score < 0.3, medium: agent.risk_score < 0.6, high: agent.risk_score < 0.8, critical: agent.risk_score >= 0.8 }">
              </div>
            </div>
            <span class="risk-label">风险 {{ riskPercent(agent.risk_score) }}%</span>
          </div>
          <div class="det-right">
            <div class="stat-mini">
              <span class="stat-num">{{ agent.event_count }}</span>
              <span class="stat-desc">事件</span>
            </div>
            <div class="stat-mini" :class="{ danger: agent.alert_count > 0 }">
              <span class="stat-num">{{ agent.alert_count }}</span>
              <span class="stat-desc">告警</span>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Agent 类型列表 -->
    <div class="card">
      <div class="card-header">
        <span>📋 支持的 Agent 类型 ({{ sortedProfiles.length }})</span>
        <button class="btn-sm" @click="loadProfiles()">🔄 刷新</button>
      </div>
      <div class="profiles-grid">
        <div
          v-for="profile in sortedProfiles" :key="profile.type"
          class="profile-card" :class="{ selected: selectedProfile?.type === profile.type }"
          @click="selectedProfile = selectedProfile?.type === profile.type ? null : profile"
        >
          <div class="profile-header">
            <span class="profile-icon">{{ agentIcons[profile.type] || '⬜' }}</span>
            <span class="profile-name">{{ profile.name }}</span>
            <span class="risk-badge" :style="{ color: riskColors[profile.risk_level] }">
              {{ profile.risk_level }}
            </span>
          </div>
          <div class="profile-desc">{{ profile.description }}</div>
          <div class="profile-stats">
            <span class="ps-item">🔍 {{ profile.process_names.length }} 进程名</span>
            <span class="ps-item">🌐 {{ profile.api_domains.length }} API域名</span>
            <span class="ps-item">⚠️ {{ rulesByAgent[profile.type] || 0 }} 规则</span>
          </div>

          <!-- 展开详情 -->
          <div v-if="selectedProfile?.type === profile.type" class="profile-details">
            <div class="detail-section">
              <h4>进程名</h4>
              <div class="tag-list">
                <span v-for="p in profile.process_names" :key="p" class="tag">{{ p }}</span>
              </div>
            </div>
            <div class="detail-section">
              <h4>API 域名</h4>
              <div class="tag-list">
                <span v-for="d in profile.api_domains" :key="d" class="tag domain">{{ d }}</span>
              </div>
            </div>
            <div class="detail-section">
              <h4>危险操作</h4>
              <div class="tag-list">
                <span v-for="op in profile.dangerous_ops" :key="op" class="tag danger">{{ op }}</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.agent-integration {
  max-width: 1200px;
}

.section-header {
  margin-bottom: 24px;
}

.section-header h2 {
  font-size: 24px;
  font-weight: 600;
  margin-bottom: 4px;
}

.subtitle {
  font-size: 14px;
  color: var(--text-secondary, #8b949e);
}

/* Overview Grid */
.overview-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: 12px;
  margin-bottom: 20px;
}

.overview-card {
  background: var(--bg-secondary, #161b22);
  border: 1px solid var(--border-color, #30363d);
  border-radius: 8px;
  padding: 16px;
  text-align: center;
  transition: border-color 0.2s;
}

.overview-card.warning { border-color: var(--color-warning, #d29922); }
.overview-card.danger { border-color: var(--color-critical, #f85149); }

.ov-value {
  font-size: 28px;
  font-weight: 700;
  color: var(--text-primary, #e6edf3);
}

.ov-label {
  font-size: 12px;
  color: var(--text-secondary, #8b949e);
  margin-top: 4px;
}

/* Card */
.card {
  background: var(--bg-secondary, #161b22);
  border: 1px solid var(--border-color, #30363d);
  border-radius: 8px;
  margin-bottom: 16px;
}

.card-header {
  padding: 14px 16px;
  font-size: 14px;
  font-weight: 600;
  border-bottom: 1px solid var(--border-color, #30363d);
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.badge {
  font-size: 10px;
  padding: 2px 8px;
  border-radius: 4px;
  background: rgba(88, 166, 255, 0.15);
  color: var(--accent-blue, #58a6ff);
}

/* Simulator */
.sim-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(130px, 1fr));
  gap: 8px;
  padding: 12px 16px;
}

.sim-btn {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 4px;
  padding: 12px 8px;
  border: 1px solid var(--border-color, #30363d);
  border-radius: 8px;
  background: var(--bg-primary, #0d1117);
  cursor: pointer;
  transition: all 0.15s;
}

.sim-btn:hover:not(:disabled) {
  transform: translateY(-2px);
  box-shadow: 0 4px 12px rgba(0,0,0,0.3);
}

.sim-btn:disabled { opacity: 0.5; cursor: not-allowed; }
.sim-btn.high:hover:not(:disabled) { border-color: var(--color-danger, #d29922); }
.sim-btn.critical:hover:not(:disabled) { border-color: var(--color-critical, #f85149); }

.sim-icon { font-size: 20px; }
.sim-name { font-size: 11px; font-weight: 600; color: var(--text-primary, #e6edf3); }
.sim-risk { font-size: 9px; color: var(--text-tertiary, #484f58); text-transform: uppercase; }

/* Detected List */
.detected-list { max-height: 400px; overflow-y: auto; }

.detected-item {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 12px 16px;
  border-bottom: 1px solid var(--border-color, #30363d);
  transition: background 0.1s;
}

.detected-item:hover { background: var(--bg-tertiary, #1c2128); }
.detected-item:last-child { border-bottom: none; }

.det-left { display: flex; align-items: center; gap: 12px; min-width: 200px; }
.det-icon { font-size: 24px; }
.det-name { font-weight: 600; font-size: 14px; }
.det-meta { font-size: 11px; color: var(--text-tertiary, #484f58); }

.det-center { flex: 1; max-width: 200px; margin: 0 20px; }

.risk-meter {
  height: 6px;
  background: var(--bg-tertiary, #1c2128);
  border-radius: 3px;
  overflow: hidden;
  margin-bottom: 4px;
}

.risk-fill {
  height: 100%;
  border-radius: 3px;
  transition: width 0.3s ease;
}

.risk-fill.low { background: #3fb950; }
.risk-fill.medium { background: #d29922; }
.risk-fill.high { background: #f0883e; }
.risk-fill.critical { background: #f85149; }

.risk-label { font-size: 10px; color: var(--text-tertiary, #484f58); }

.det-right { display: flex; gap: 16px; }

.stat-mini { text-align: center; }
.stat-num { display: block; font-weight: 700; font-size: 16px; }
.stat-desc { font-size: 10px; color: var(--text-tertiary, #484f58); }
.stat-mini.danger .stat-num { color: var(--color-critical, #f85149); }

/* Profile Grid */
.profiles-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(320px, 1fr));
  gap: 12px;
  padding: 16px;
}

.profile-card {
  border: 1px solid var(--border-color, #30363d);
  border-radius: 8px;
  padding: 14px;
  cursor: pointer;
  transition: all 0.15s;
}

.profile-card:hover { border-color: var(--accent-blue, #58a6ff); }
.profile-card.selected { border-color: var(--accent-blue, #58a6ff); background: rgba(88, 166, 255, 0.05); }

.profile-header {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 6px;
}

.profile-icon { font-size: 18px; }
.profile-name { font-weight: 600; font-size: 14px; flex: 1; }
.risk-badge { font-size: 10px; font-weight: 700; text-transform: uppercase; }

.profile-desc {
  font-size: 12px;
  color: var(--text-secondary, #8b949e);
  margin-bottom: 8px;
}

.profile-stats {
  display: flex;
  gap: 12px;
}

.ps-item {
  font-size: 11px;
  color: var(--text-tertiary, #484f58);
}

/* Profile Details */
.profile-details {
  margin-top: 12px;
  padding-top: 12px;
  border-top: 1px solid var(--border-color, #30363d);
}

.detail-section { margin-bottom: 10px; }
.detail-section h4 { font-size: 11px; color: var(--text-tertiary, #484f58); margin-bottom: 6px; text-transform: uppercase; letter-spacing: 0.5px; }

.tag-list { display: flex; flex-wrap: wrap; gap: 4px; }

.tag {
  font-size: 10px;
  padding: 2px 8px;
  border-radius: 4px;
  background: var(--bg-tertiary, #1c2128);
  color: var(--text-secondary, #8b949e);
  font-family: monospace;
}

.tag.domain { background: rgba(88, 166, 255, 0.1); color: var(--accent-blue, #58a6ff); }
.tag.danger { background: rgba(248, 81, 73, 0.1); color: var(--color-critical, #f85149); }

.btn-sm {
  font-size: 11px;
  padding: 4px 10px;
  border: 1px solid var(--border-color, #30363d);
  border-radius: 4px;
  background: var(--bg-primary, #0d1117);
  color: var(--text-secondary, #8b949e);
  cursor: pointer;
}
.btn-sm:hover { color: var(--text-primary, #e6edf3); }
</style>
