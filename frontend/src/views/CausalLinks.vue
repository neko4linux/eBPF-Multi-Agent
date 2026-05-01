<template>
  <div class="causal-view">
    <div class="page-header">
      <h1>因果关联分析</h1>
      <button class="btn btn-primary" @click="fetch">🔄 刷新</button>
    </div>

    <div class="card">
      <div class="card-header">
        <span>跨层因果关系 ({{ causalLinks.length }})</span>
        <span class="info">通过 eBPF 多层事件关联自动发现</span>
      </div>
      <div class="links-list">
        <div v-for="link in causalLinks" :key="link.id" class="link-item">
          <div class="link-header">
            <span class="relationship">{{ link.relationship }}</span>
            <span class="confidence" :style="{ color: confidenceColor(link.confidence) }">
              置信度: {{ (link.confidence * 100).toFixed(0) }}%
            </span>
          </div>
          <div class="link-flow">
            <code>{{ link.source_event_id.slice(0, 8) }}</code>
            <span class="arrow">→</span>
            <code>{{ link.target_event_id.slice(0, 8) }}</code>
          </div>
          <div class="link-desc">{{ link.description }}</div>
          <div class="link-time">{{ formatTime(link.created_at) }}</div>
        </div>
        <div v-if="causalLinks.length === 0" class="empty">暂未发现因果关联</div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useDashboardStore } from '@/stores/dashboard'
import type { CausalLink } from '@/types'

const store = useDashboardStore()
const causalLinks = ref<CausalLink[]>([])

async function fetch() {
  await store.fetchCausalLinks()
  causalLinks.value = store.causalLinks
}

onMounted(() => fetch())

function confidenceColor(c: number): string {
  if (c >= 0.8) return 'var(--accent-green)'
  if (c >= 0.5) return 'var(--accent-yellow)'
  return 'var(--accent-red)'
}

function formatTime(t: string) {
  return new Date(t).toLocaleString('zh-CN')
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

.info {
  font-size: 11px;
  color: var(--text-muted);
  font-weight: 400;
}

.links-list {
  max-height: 600px;
  overflow-y: auto;
}

.link-item {
  padding: 16px;
  border-bottom: 1px solid var(--border-color);
}

.link-item:hover {
  background: var(--bg-tertiary);
}

.link-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 8px;
}

.relationship {
  background: rgba(188, 140, 255, 0.15);
  color: var(--accent-purple);
  padding: 2px 10px;
  border-radius: 12px;
  font-size: 12px;
  font-weight: 500;
}

.confidence {
  font-size: 12px;
  font-weight: 600;
}

.link-flow {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 8px;
}

.link-flow code {
  background: var(--bg-tertiary);
  padding: 2px 8px;
  border-radius: 4px;
  font-size: 12px;
  color: var(--accent-blue);
}

.arrow {
  color: var(--text-muted);
}

.link-desc {
  color: var(--text-secondary);
  font-size: 13px;
  margin-bottom: 4px;
}

.link-time {
  color: var(--text-muted);
  font-size: 11px;
}

.empty {
  text-align: center;
  color: var(--text-muted);
  padding: 48px;
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
