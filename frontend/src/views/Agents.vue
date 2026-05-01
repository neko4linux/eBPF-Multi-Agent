<template>
  <div class="agents-view">
    <div class="page-header">
      <h1>智能体管理</h1>
      <div class="header-actions">
        <button class="btn btn-primary" @click="refresh">🔄 刷新</button>
      </div>
    </div>

    <div class="card">
      <div class="card-header">
        <span>所有智能体 ({{ store.agents.length }})</span>
        <span class="summary">
          运行中: <strong class="green">{{ runningCount }}</strong> |
          错误: <strong class="red">{{ errorCount }}</strong>
        </span>
      </div>
      <AgentTable :agents="store.agents" @stop="onStop" />
    </div>

    <div class="card">
      <div class="card-header">生成新智能体</div>
      <div class="spawn-grid">
        <button class="spawn-btn" @click="store.spawnAgent('network')">🌐 网络监控智能体</button>
        <button class="spawn-btn" @click="store.spawnAgent('process')">⚙️ 进程监控智能体</button>
        <button class="spawn-btn" @click="store.spawnAgent('security')">🛡️ 安全监控智能体</button>
        <button class="spawn-btn" @click="store.spawnAgent('filesystem')">📁 文件监控智能体</button>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted } from 'vue'
import { useDashboardStore } from '@/stores/dashboard'
import { useApi } from '@/composables/useApi'
import AgentTable from '@/components/AgentTable.vue'

const store = useDashboardStore()
const api = useApi()

onMounted(() => store.fetchAll())

const runningCount = computed(() => store.agents.filter(a => a.status === 'running').length)
const errorCount = computed(() => store.agents.filter(a => a.status === 'error').length)

function refresh() { store.fetchAll() }
async function onStop(id: string) {
  await api.stopAgent(id)
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

.green { color: var(--accent-green); }
.red { color: var(--accent-red); }

.summary {
  font-size: 12px;
  color: var(--text-secondary);
  font-weight: 400;
}

.spawn-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 12px;
  padding: 16px;
}

.spawn-btn {
  padding: 16px;
  border: 1px solid var(--border-color);
  border-radius: 8px;
  background: var(--bg-tertiary);
  color: var(--text-primary);
  cursor: pointer;
  font-size: 14px;
  transition: all 0.15s ease;
}

.spawn-btn:hover {
  border-color: var(--accent-blue);
  background: rgba(88, 166, 255, 0.1);
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
