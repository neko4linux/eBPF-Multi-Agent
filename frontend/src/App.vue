<template>
  <div class="app-layout">
    <nav class="sidebar">
      <div class="sidebar-header">
        <h2>⚡ eBPF 多智能体</h2>
        <span class="version">v0.2.0</span>
      </div>
      <ul class="nav-list">
        <li>
          <router-link to="/" class="nav-link" active-class="active">
            <span class="nav-icon">📊</span>
            <span class="nav-text">仪表盘</span>
          </router-link>
        </li>
        <li>
          <router-link to="/agents" class="nav-link" active-class="active">
            <span class="nav-icon">🤖</span>
            <span class="nav-text">智能体</span>
          </router-link>
        </li>
        <li>
          <router-link to="/integrations" class="nav-link" active-class="active">
            <span class="nav-icon">🔗</span>
            <span class="nav-text">Agent 集成</span>
            <span v-if="detectedCount > 0" class="nav-badge">{{ detectedCount }}</span>
          </router-link>
        </li>
        <li>
          <router-link to="/alerts" class="nav-link" active-class="active">
            <span class="nav-icon">🔔</span>
            <span class="nav-text">告警</span>
            <span v-if="alertCount > 0" class="nav-badge danger">{{ alertCount }}</span>
          </router-link>
        </li>
        <li>
          <router-link to="/causal-links" class="nav-link" active-class="active">
            <span class="nav-icon">🔗</span>
            <span class="nav-text">因果关联</span>
          </router-link>
        </li>
        <li>
          <router-link to="/rules" class="nav-link" active-class="active">
            <span class="nav-icon">📋</span>
            <span class="nav-text">检测规则</span>
          </router-link>
        </li>
      </ul>
      <div class="sidebar-footer">
        <div class="system-info">
          <span class="connection-status" :class="{ connected: wsConnected }">
            {{ wsConnected ? '● 实时连接' : '○ 离线模式' }}
          </span>
          <span class="agent-count" v-if="detectedCount > 0">
            🤖 {{ detectedCount }} 个 Agent 活跃
          </span>
        </div>
      </div>
    </nav>
    <main class="main-content">
      <router-view />
    </main>
  </div>
</template>

<script setup lang="ts">
import { computed, watch } from 'vue'
import { useWebSocket } from '@/composables/useWebSocket'
import { useDashboardStore } from '@/stores/dashboard'

const store = useDashboardStore()
const { data, isConnected: wsConnected } = useWebSocket('/api/ws')

const detectedCount = computed(() => store.agents.length)
const alertCount = computed(() => store.alerts.filter(a => !a.acknowledged).length)

watch(data, (msg) => {
  if (msg) store.handleWSMessage(msg)
})
</script>

<style scoped>
.app-layout {
  display: flex;
  min-height: 100vh;
}

.sidebar {
  width: 240px;
  background: var(--bg-secondary);
  border-right: 1px solid var(--border-color);
  display: flex;
  flex-direction: column;
  position: fixed;
  top: 0;
  left: 0;
  bottom: 0;
  z-index: 10;
}

.sidebar-header {
  padding: 20px 16px;
  border-bottom: 1px solid var(--border-color);
  display: flex;
  align-items: baseline;
  gap: 8px;
}

.sidebar-header h2 {
  font-size: 16px;
  font-weight: 600;
  color: var(--text-primary);
}

.version {
  font-size: 10px;
  color: var(--text-tertiary);
  background: var(--bg-tertiary);
  padding: 2px 6px;
  border-radius: 4px;
}

.nav-list {
  list-style: none;
  padding: 8px;
  flex: 1;
}

.nav-list li {
  margin-bottom: 2px;
}

.nav-link {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 10px 12px;
  color: var(--text-secondary);
  text-decoration: none;
  border-radius: 6px;
  font-size: 14px;
  transition: all 0.15s ease;
  position: relative;
}

.nav-link:hover {
  background: var(--bg-tertiary);
  color: var(--text-primary);
}

.nav-link.active {
  background: var(--bg-tertiary);
  color: var(--accent-blue);
  font-weight: 500;
}

.nav-link.active .nav-icon {
  transform: scale(1.1);
}

.nav-icon {
  font-size: 16px;
  width: 20px;
  text-align: center;
  transition: transform 0.15s ease;
}

.nav-badge {
  margin-left: auto;
  background: var(--accent-blue);
  color: white;
  font-size: 10px;
  font-weight: 600;
  padding: 2px 6px;
  border-radius: 10px;
  min-width: 18px;
  text-align: center;
}

.nav-badge.danger {
  background: var(--accent-red);
}

.sidebar-footer {
  padding: 16px;
  border-top: 1px solid var(--border-color);
}

.system-info {
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.connection-status {
  font-size: 12px;
  color: var(--accent-red);
}

.connection-status.connected {
  color: var(--accent-green);
}

.agent-count {
  font-size: 11px;
  color: var(--text-tertiary);
}

.main-content {
  flex: 1;
  margin-left: 240px;
  padding: 24px;
  min-height: 100vh;
  background: var(--bg-primary);
}
</style>
