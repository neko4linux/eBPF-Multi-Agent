<template>
  <div class="rules-view">
    <div class="page-header">
      <h1>📋 检测规则</h1>
      <div class="header-actions">
        <span class="rule-count">共 {{ rules.length }} 条规则</span>
        <button class="btn btn-primary" @click="loadRules">🔄 刷新</button>
      </div>
    </div>

    <!-- Filter -->
    <div class="filter-bar">
      <button
        v-for="sev in severities" :key="sev"
        class="filter-btn" :class="{ active: filter === sev }"
        @click="filter = filter === sev ? '' : sev"
      >
        {{ sev }}
        <span class="filter-count">{{ countBySeverity(sev) }}</span>
      </button>
    </div>

    <!-- Rules Table -->
    <div class="card">
      <div class="card-header">
        <span>异常检测规则库</span>
        <span class="subtitle">{{ filtered.length }} 条显示</span>
      </div>
      <div class="rules-list">
        <div v-for="rule in filtered" :key="rule.name" class="rule-item" :class="rule.severity.toLowerCase()">
          <div class="rule-header">
            <span class="severity-badge" :class="rule.severity.toLowerCase()">{{ rule.severity }}</span>
            <span class="rule-name">{{ rule.name }}</span>
            <span class="agent-badge">{{ rule.agent_type || 'ALL' }}</span>
          </div>
          <div class="rule-desc">{{ rule.description }}</div>
          <div class="rule-meta">
            <span class="event-type">📡 {{ rule.event_type }}</span>
            <div class="keywords">
              <span v-for="kw in rule.keywords" :key="kw" class="keyword">{{ kw }}</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { useApi } from '@/composables/useApi'
import type { AnomalyRule } from '@/composables/useApi'

const api = useApi()
const rules = ref<AnomalyRule[]>([])
const filter = ref('')

const severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']

const filtered = computed(() => {
  if (!filter.value) return rules.value
  return rules.value.filter(r => r.severity === filter.value)
})

function countBySeverity(sev: string) {
  return rules.value.filter(r => r.severity === sev).length
}

async function loadRules() {
  try {
    rules.value = await api.getAnomalyRules()
  } catch (e) {
    console.error('Failed to load rules:', e)
  }
}

onMounted(loadRules)
</script>

<style scoped>
.page-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 20px;
}

.page-header h1 { font-size: 24px; font-weight: 600; }

.header-actions {
  display: flex;
  align-items: center;
  gap: 12px;
}

.rule-count {
  font-size: 13px;
  color: var(--text-secondary);
}

.filter-bar {
  display: flex;
  gap: 8px;
  margin-bottom: 20px;
  flex-wrap: wrap;
}

.filter-btn {
  padding: 6px 14px;
  border: 1px solid var(--border-color);
  border-radius: 20px;
  background: var(--bg-secondary);
  color: var(--text-secondary);
  cursor: pointer;
  font-size: 12px;
  font-weight: 500;
  transition: all 0.15s ease;
  display: flex;
  align-items: center;
  gap: 6px;
}

.filter-btn:hover { border-color: var(--accent-blue); color: var(--text-primary); }
.filter-btn.active { background: rgba(88, 166, 255, 0.15); border-color: var(--accent-blue); color: var(--accent-blue); }

.filter-count {
  background: var(--bg-tertiary);
  padding: 1px 6px;
  border-radius: 10px;
  font-size: 10px;
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

.subtitle { font-size: 12px; color: var(--text-tertiary); font-weight: 400; }

.rules-list {
  max-height: calc(100vh - 280px);
  overflow-y: auto;
}

.rule-item {
  padding: 14px 16px;
  border-bottom: 1px solid var(--border-color);
  transition: background 0.1s;
}

.rule-item:hover { background: var(--bg-tertiary); }
.rule-item:last-child { border-bottom: none; }

.rule-header {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-bottom: 6px;
}

.severity-badge {
  font-size: 10px;
  font-weight: 700;
  padding: 2px 8px;
  border-radius: 4px;
  text-transform: uppercase;
}

.severity-badge.critical { background: rgba(248, 81, 73, 0.15); color: #f85149; }
.severity-badge.high { background: rgba(210, 153, 34, 0.15); color: #d29922; }
.severity-badge.medium { background: rgba(88, 166, 255, 0.15); color: #58a6ff; }
.severity-badge.low { background: rgba(63, 185, 80, 0.15); color: #3fb950; }

.rule-name { font-weight: 600; font-size: 13px; font-family: monospace; }

.agent-badge {
  font-size: 10px;
  padding: 2px 8px;
  border-radius: 4px;
  background: var(--bg-tertiary);
  color: var(--text-tertiary);
  margin-left: auto;
}

.rule-desc { font-size: 13px; color: var(--text-secondary); margin-bottom: 8px; }

.rule-meta {
  display: flex;
  align-items: center;
  gap: 12px;
  flex-wrap: wrap;
}

.event-type { font-size: 11px; color: var(--text-tertiary); }

.keywords {
  display: flex;
  gap: 4px;
  flex-wrap: wrap;
}

.keyword {
  font-size: 10px;
  padding: 1px 6px;
  border-radius: 3px;
  background: var(--bg-tertiary);
  color: var(--text-tertiary);
  font-family: monospace;
}

.btn { padding: 8px 16px; border: 1px solid var(--border-color); border-radius: 6px; background: var(--bg-secondary); color: var(--text-primary); cursor: pointer; font-size: 13px; }
.btn-primary { background: rgba(88, 166, 255, 0.15); border-color: var(--accent-blue); color: var(--accent-blue); }
</style>
