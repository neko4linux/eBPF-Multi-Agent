<template>
  <div class="dashboard">
    <div class="page-header">
      <h1>监控仪表盘</h1>
      <button class="btn btn-primary" @click="store.fetchAll()">🔄 刷新</button>
    </div>

    <!-- Stats -->
    <div class="stats-bar">
      <div class="stat-card">
        <div class="stat-value">{{ store.stats.total_agents }}</div>
        <div class="stat-label">智能体总数</div>
      </div>
      <div class="stat-card">
        <div class="stat-value green">{{ store.stats.running_agents }}</div>
        <div class="stat-label">运行中</div>
      </div>
      <div class="stat-card">
        <div class="stat-value blue">{{ store.stats.total_events }}</div>
        <div class="stat-label">事件总数</div>
      </div>
      <div class="stat-card">
        <div class="stat-value yellow">{{ store.stats.total_alerts }}</div>
        <div class="stat-label">告警总数</div>
      </div>
      <div class="stat-card">
        <div class="stat-value red">{{ store.stats.critical_alerts }}</div>
        <div class="stat-label">严重告警</div>
      </div>
    </div>

    <!-- Control Panel -->
    <div class="card">
      <div class="card-header">控制面板</div>
      <ControlPanel @spawn="store.spawnAgent" @scenario="store.triggerScenario" />
    </div>

    <div class="grid-2">
      <!-- Agents -->
      <div class="card">
        <div class="card-header">智能体状态</div>
        <AgentTable :agents="store.agents" @stop="api.stopAgent($event).then(() => store.fetchAll())" />
      </div>

      <!-- Alerts -->
      <div class="card">
        <div class="card-header">最新告警</div>
        <AlertList :alerts="store.alerts.slice(0, 10)" @acknowledge="onAck" />
      </div>
    </div>

    <!-- Event Log -->
    <div class="card">
      <div class="card-header">
        实时事件流
        <span class="ws-indicator" :class="{ live: wsConnected }">
          {{ wsConnected ? '● 实时' : '○ 离线' }}
        </span>
      </div>
      <EventLog :events="store.events.slice(0, 50)" />
    </div>
  </div>
</template>

<script setup lang="ts">
import { onMounted } from 'vue'
import { useDashboardStore } from '@/stores/dashboard'
import { useApi } from '@/composables/useApi'
import { useWebSocket } from '@/composables/useWebSocket'
import AgentTable from '@/components/AgentTable.vue'
import EventLog from '@/components/EventLog.vue'
import AlertList from '@/components/AlertList.vue'
import ControlPanel from '@/components/ControlPanel.vue'

const store = useDashboardStore()
const api = useApi()
const { isConnected: wsConnected } = useWebSocket('/api/ws')

onMounted(() => store.fetchAll())

async function onAck(id: string) {
  await api.acknowledgeAlert(id)
  await store.fetchAll()
}
</script>

<style scoped>
.page-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 24px;
}

.page-header h1 {
  font-size: 24px;
  font-weight: 600;
}

.stats-bar {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
  gap: 12px;
  margin-bottom: 24px;
}

.stat-card {
  background: var(--bg-secondary);
  border: 1px solid var(--border-color);
  border-radius: 8px;
  padding: 16px;
  text-align: center;
}

.stat-value {
  font-size: 28px;
  font-weight: 700;
  color: var(--text-primary);
}

.stat-value.green { color: var(--accent-green); }
.stat-value.blue { color: var(--accent-blue); }
.stat-value.yellow { color: var(--accent-yellow); }
.stat-value.red { color: var(--accent-red); }

.stat-label {
  font-size: 12px;
  color: var(--text-secondary);
  margin-top: 4px;
}

.card {
  background: var(--bg-secondary);
  border: 1px solid var(--border-color);
  border-radius: 8px;
  margin-bottom: 16px;
}

.card-header {
  padding: 14px 16px;
  font-size: 14px;
  font-weight: 600;
  border-bottom: 1px solid var(--border-color);
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.ws-indicator {
  font-size: 12px;
  color: var(--accent-red);
}

.ws-indicator.live {
  color: var(--accent-green);
}

.grid-2 {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 16px;
  margin-bottom: 16px;
}

@media (max-width: 900px) {
  .grid-2 {
    grid-template-columns: 1fr;
  }
}

.btn {
  padding: 8px 16px;
  border: 1px solid var(--border-color);
  border-radius: 6px;
  background: var(--bg-secondary);
  color: var(--text-primary);
  cursor: pointer;
  font-size: 13px;
}

.btn-primary {
  background: rgba(88, 166, 255, 0.15);
  border-color: var(--accent-blue);
  color: var(--accent-blue);
}
</style>
