<template>
  <div class="app-layout">
    <nav class="sidebar">
      <div class="sidebar-header">
        <h2>⚡ eBPF 多智能体</h2>
      </div>
      <ul class="nav-list">
        <li>
          <router-link to="/" class="nav-link" active-class="active">
            📊 仪表盘
          </router-link>
        </li>
        <li>
          <router-link to="/agents" class="nav-link" active-class="active">
            🤖 智能体
          </router-link>
        </li>
        <li>
          <router-link to="/alerts" class="nav-link" active-class="active">
            🔔 告警
          </router-link>
        </li>
        <li>
          <router-link to="/causal-links" class="nav-link" active-class="active">
            🔗 因果关联
          </router-link>
        </li>
      </ul>
      <div class="sidebar-footer">
        <span class="connection-status" :class="{ connected: wsConnected }">
          {{ wsConnected ? '● 已连接' : '○ 断开' }}
        </span>
      </div>
    </nav>
    <main class="main-content">
      <router-view />
    </main>
  </div>
</template>

<script setup lang="ts">
import { watch } from 'vue'
import { useWebSocket } from '@/composables/useWebSocket'
import { useDashboardStore } from '@/stores/dashboard'

const store = useDashboardStore()
const { data, isConnected: wsConnected } = useWebSocket('/api/ws')

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
}

.sidebar-header h2 {
  font-size: 16px;
  font-weight: 600;
  color: var(--text-primary);
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
  display: block;
  padding: 10px 12px;
  color: var(--text-secondary);
  text-decoration: none;
  border-radius: 6px;
  font-size: 14px;
  transition: all 0.15s ease;
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

.sidebar-footer {
  padding: 16px;
  border-top: 1px solid var(--border-color);
}

.connection-status {
  font-size: 12px;
  color: var(--accent-red);
}

.connection-status.connected {
  color: var(--accent-green);
}

.main-content {
  flex: 1;
  margin-left: 240px;
  padding: 24px;
  min-height: 100vh;
  background: var(--bg-primary);
}
</style>
