<template>
  <div class="alerts-view">
    <div class="page-header">
      <h1>告警历史</h1>
      <button class="btn btn-primary" @click="store.fetchAll()">🔄 刷新</button>
    </div>

    <div class="filter-bar">
      <button
        v-for="sev in severities"
        :key="sev"
        class="filter-btn"
        :class="{ active: selectedSeverity === sev }"
        @click="selectedSeverity = selectedSeverity === sev ? null : sev"
      >
        {{ sevLabels[sev] }} ({{ countBySeverity(sev) }})
      </button>
      <button
        class="filter-btn"
        :class="{ active: showUnackOnly }"
        @click="showUnackOnly = !showUnackOnly"
      >
        仅未确认
      </button>
    </div>

    <div class="card">
      <div class="card-header">
        <span>告警列表 ({{ filtered.length }})</span>
        <span class="stats">
          严重: <strong class="red">{{ store.stats.critical_alerts }}</strong>
        </span>
      </div>
      <AlertList :alerts="filtered" @acknowledge="onAck" />
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { useDashboardStore } from '@/stores/dashboard'
import { useApi } from '@/composables/useApi'
import AlertList from '@/components/AlertList.vue'
import type { AlertSeverity } from '@/types'

const store = useDashboardStore()
const api = useApi()

const severities: AlertSeverity[] = ['critical', 'high', 'medium', 'low', 'info']
const sevLabels: Record<AlertSeverity, string> = {
  critical: '严重', high: '高', medium: '中', low: '低', info: '信息',
}

const selectedSeverity = ref<AlertSeverity | null>(null)
const showUnackOnly = ref(false)

const filtered = computed(() => {
  let list = store.alerts
  if (selectedSeverity.value) list = list.filter(a => a.severity === selectedSeverity.value)
  if (showUnackOnly.value) list = list.filter(a => !a.acknowledged)
  return list
})

function countBySeverity(sev: AlertSeverity) {
  return store.alerts.filter(a => a.severity === sev).length
}

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

.filter-bar {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  margin-bottom: 16px;
}

.filter-btn {
  padding: 6px 14px;
  border: 1px solid var(--border-color);
  border-radius: 20px;
  background: var(--bg-secondary);
  color: var(--text-secondary);
  cursor: pointer;
  font-size: 12px;
}

.filter-btn:hover {
  border-color: var(--text-muted);
}

.filter-btn.active {
  background: rgba(88, 166, 255, 0.15);
  border-color: var(--accent-blue);
  color: var(--accent-blue);
}

.card {
  background: var(--bg-secondary);
  border: 1px solid var(--border-color);
  border-radius: 8px;
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

.stats {
  font-size: 12px;
  color: var(--text-secondary);
  font-weight: 400;
}

.red { color: var(--accent-red); }

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
