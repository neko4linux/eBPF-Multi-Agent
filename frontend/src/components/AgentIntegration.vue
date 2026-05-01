<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { useApi } from '../composables/useApi'

interface AgentProfile {
  type: string
  name: string
  description: string
  process_names: string[]
  api_domains: string[]
  risk_level: string
  dangerous_ops: string[]
}

interface DetectedAgent {
  pid: number
  name: string
  type: string
  profile: AgentProfile
  first_seen: string
  last_seen: string
  event_count: number
  alert_count: number
  risk_score: number
}

const api = useApi()
const profiles = ref<AgentProfile[]>([])
const detected = ref<DetectedAgent[]>([])
const selectedProfile = ref<AgentProfile | null>(null)

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
  'LOW': 'var(--color-success)',
  'MEDIUM': 'var(--color-warning)',
  'HIGH': 'var(--color-danger)',
  'CRITICAL': 'var(--color-critical)',
}

const sortedProfiles = computed(() => {
  return [...profiles.value].sort((a, b) => {
    const order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
    return order.indexOf(a.risk_level) - order.indexOf(b.risk_level)
  })
})

const activeAgents = computed(() => detected.value.filter(a => a.risk_score > 0.3))

async function loadProfiles() {
  try {
    const data = await api.get('/api/agents/profiles')
    profiles.value = data || []
  } catch { /* ignore */ }
}

async function loadDetected() {
  try {
    const data = await api.get('/api/agents/detected')
    detected.value = data || []
  } catch { /* ignore */ }
}

onMounted(() => {
  loadProfiles()
  loadDetected()
})
</script>

<template>
  <div class="agent-integration">
    <header class="section-header">
      <h2>🤖 AI Agent 集成监控</h2>
      <p class="subtitle">实时检测和监控系统中运行的 AI 编程助手</p>
    </header>

    <!-- 已检测到的 Agent -->
    <section class="detected-section" v-if="detected.length">
      <h3>🔍 已检测到的 Agent</h3>
      <div class="agent-grid">
        <div
          v-for="agent in detected"
          :key="agent.pid"
          class="agent-card detected"
          :style="{ borderColor: riskColors[agent.profile?.risk_level || 'LOW'] }"
        >
          <div class="agent-icon">{{ agentIcons[agent.type] || '⬜' }}</div>
          <div class="agent-info">
            <div class="agent-name">{{ agent.name }}</div>
            <div class="agent-type">{{ agent.type }}</div>
            <div class="agent-pid">PID: {{ agent.pid }}</div>
          </div>
          <div class="agent-stats">
            <div class="stat">
              <span class="stat-num">{{ agent.event_count }}</span>
              <span class="stat-label">事件</span>
            </div>
            <div class="stat" :class="{ 'has-alerts': agent.alert_count > 0 }">
              <span class="stat-num">{{ agent.alert_count }}</span>
              <span class="stat-label">告警</span>
            </div>
            <div class="stat">
              <span class="stat-num">{{ (agent.risk_score * 100).toFixed(0) }}%</span>
              <span class="stat-label">风险</span>
            </div>
          </div>
        </div>
      </div>
    </section>

    <!-- Agent 配置文件 -->
    <section class="profiles-section">
      <h3>📋 支持的 AI Agent</h3>
      <div class="profiles-grid">
        <div
          v-for="profile in sortedProfiles"
          :key="profile.type"
          class="profile-card"
          :class="{ selected: selectedProfile?.type === profile.type }"
          @click="selectedProfile = profile"
        >
          <div class="profile-header">
            <span class="profile-icon">{{ agentIcons[profile.type] || '⬜' }}</span>
            <span class="profile-name">{{ profile.name }}</span>
            <span
              class="risk-badge"
              :style="{ background: riskColors[profile.risk_level] }"
            >
              {{ profile.risk_level }}
            </span>
          </div>
          <p class="profile-desc">{{ profile.description }}</p>
          <div class="profile-domains">
            <span v-for="d in profile.api_domains" :key="d" class="domain-tag">
              {{ d }}
            </span>
          </div>
        </div>
      </div>
    </section>

    <!-- Agent 详情面板 -->
    <section v-if="selectedProfile" class="detail-panel">
      <div class="detail-header">
        <span class="detail-icon">{{ agentIcons[selectedProfile.type] }}</span>
        <h3>{{ selectedProfile.name }} — 集成详情</h3>
        <button class="close-btn" @click="selectedProfile = null">✕</button>
      </div>

      <div class="detail-grid">
        <div class="detail-section">
          <h4>🔍 进程识别</h4>
          <div class="tag-list">
            <span v-for="n in selectedProfile.process_names" :key="n" class="tag">{{ n }}</span>
          </div>
        </div>

        <div class="detail-section">
          <h4>🌐 API 域名</h4>
          <div class="tag-list">
            <span v-for="d in selectedProfile.api_domains" :key="d" class="tag domain">{{ d }}</span>
          </div>
        </div>

        <div class="detail-section">
          <h4>⚠️ 风险操作</h4>
          <ul class="risk-list">
            <li v-for="op in selectedProfile.dangerous_ops" :key="op" class="risk-item">
              {{ op }}
            </li>
          </ul>
        </div>

        <div class="detail-section">
          <h4>📊 监控能力</h4>
          <ul class="capability-list">
            <li class="cap-item">✅ 进程名/命令行识别</li>
            <li class="cap-item">✅ SSL/TLS 流量拦截 (uprobe)</li>
            <li class="cap-item">✅ Prompt/Response 提取</li>
            <li class="cap-item">✅ 异常行为检测</li>
            <li class="cap-item">✅ Prompt 注入检测</li>
            <li class="cap-item">✅ 数据外传检测</li>
          </ul>
        </div>
      </div>
    </section>
  </div>
</template>

<style scoped>
.agent-integration {
  padding: 20px;
}

.section-header h2 {
  margin: 0;
  font-size: 20px;
  color: var(--color-text);
}

.subtitle {
  color: var(--color-text-secondary);
  margin: 4px 0 20px;
}

h3 {
  font-size: 16px;
  color: var(--color-text);
  margin: 20px 0 12px;
}

/* Agent 卡片 */
.agent-grid, .profiles-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(320px, 1fr));
  gap: 12px;
}

.agent-card, .profile-card {
  background: var(--color-bg-secondary);
  border: 1px solid var(--color-border);
  border-radius: 8px;
  padding: 16px;
  cursor: pointer;
  transition: all 0.2s;
}

.agent-card:hover, .profile-card:hover {
  border-color: var(--color-accent);
  transform: translateY(-1px);
}

.agent-card {
  display: flex;
  gap: 12px;
  align-items: center;
  border-left: 3px solid;
}

.agent-icon {
  font-size: 32px;
}

.agent-info {
  flex: 1;
}

.agent-name {
  font-weight: 600;
  font-size: 14px;
}

.agent-type {
  color: var(--color-text-secondary);
  font-size: 12px;
  font-family: monospace;
}

.agent-pid {
  color: var(--color-text-secondary);
  font-size: 11px;
}

.agent-stats {
  display: flex;
  gap: 16px;
}

.stat {
  text-align: center;
}

.stat-num {
  display: block;
  font-size: 18px;
  font-weight: 700;
}

.stat-label {
  font-size: 10px;
  color: var(--color-text-secondary);
  text-transform: uppercase;
}

.has-alerts .stat-num {
  color: var(--color-danger);
}

/* 配置文件卡片 */
.profile-header {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 8px;
}

.profile-icon {
  font-size: 24px;
}

.profile-name {
  font-weight: 600;
  font-size: 14px;
  flex: 1;
}

.risk-badge {
  padding: 2px 8px;
  border-radius: 10px;
  font-size: 10px;
  font-weight: 600;
  color: white;
}

.profile-desc {
  color: var(--color-text-secondary);
  font-size: 12px;
  margin: 0 0 8px;
}

.profile-domains {
  display: flex;
  flex-wrap: wrap;
  gap: 4px;
}

.domain-tag {
  background: var(--color-bg-tertiary);
  padding: 2px 6px;
  border-radius: 4px;
  font-size: 10px;
  font-family: monospace;
  color: var(--color-text-secondary);
}

/* 详情面板 */
.detail-panel {
  background: var(--color-bg-secondary);
  border: 1px solid var(--color-border);
  border-radius: 8px;
  padding: 20px;
  margin-top: 20px;
}

.detail-header {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 16px;
}

.detail-header h3 {
  margin: 0;
  flex: 1;
}

.close-btn {
  background: none;
  border: none;
  color: var(--color-text-secondary);
  cursor: pointer;
  font-size: 18px;
}

.detail-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 16px;
}

.detail-section h4 {
  font-size: 13px;
  margin: 0 0 8px;
  color: var(--color-text);
}

.tag-list {
  display: flex;
  flex-wrap: wrap;
  gap: 4px;
}

.tag {
  background: var(--color-bg-tertiary);
  padding: 3px 8px;
  border-radius: 4px;
  font-size: 11px;
  font-family: monospace;
}

.tag.domain {
  color: var(--color-accent);
}

.risk-list, .capability-list {
  list-style: none;
  padding: 0;
  margin: 0;
}

.risk-item, .cap-item {
  padding: 4px 0;
  font-size: 12px;
  color: var(--color-text-secondary);
}

.risk-item::before {
  content: "⚠️ ";
}
</style>
