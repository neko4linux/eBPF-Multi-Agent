<template>
  <div class="alert-list">
    <div
      v-for="alert in alerts"
      :key="alert.id"
      class="alert-item"
      :class="{ acknowledged: alert.acknowledged }"
    >
      <span class="severity-badge" :class="'severity-' + alert.severity">
        {{ severityLabel(alert.severity) }}
      </span>
      <div class="alert-content">
        <div class="alert-title">{{ alert.title }}</div>
        <div class="alert-desc">{{ alert.description }}</div>
      </div>
      <span class="alert-time">{{ formatTime(alert.created_at) }}</span>
      <button
        v-if="!alert.acknowledged"
        class="btn btn-sm"
        @click="$emit('acknowledge', alert.id)"
      >确认</button>
    </div>
    <div v-if="alerts.length === 0" class="empty">暂无告警</div>
  </div>
</template>

<script setup lang="ts">
import type { Alert, AlertSeverity } from '@/types'

defineProps<{ alerts: Alert[] }>()
defineEmits<{ acknowledge: [id: string] }>()

const severityLabels: Record<AlertSeverity, string> = {
  critical: '严重',
  high: '高',
  medium: '中',
  low: '低',
  info: '信息',
}

function severityLabel(s: AlertSeverity) {
  return severityLabels[s] || s
}

function formatTime(t: string) {
  return new Date(t).toLocaleString('zh-CN')
}
</script>

<style scoped>
.alert-list {
  max-height: 400px;
  overflow-y: auto;
}

.alert-item {
  display: flex;
  align-items: flex-start;
  gap: 12px;
  padding: 12px;
  border-bottom: 1px solid var(--border-color);
}

.alert-item:hover {
  background: var(--bg-tertiary);
}

.alert-item.acknowledged {
  opacity: 0.5;
}

.severity-badge {
  flex-shrink: 0;
  padding: 2px 8px;
  border-radius: 12px;
  font-size: 11px;
  font-weight: 600;
  min-width: 48px;
  text-align: center;
}

.severity-critical {
  background: rgba(248, 81, 73, 0.2);
  color: var(--accent-red);
}

.severity-high {
  background: rgba(240, 136, 62, 0.2);
  color: var(--accent-orange);
}

.severity-medium {
  background: rgba(210, 153, 34, 0.2);
  color: var(--accent-yellow);
}

.severity-low {
  background: rgba(63, 185, 80, 0.2);
  color: var(--accent-green);
}

.severity-info {
  background: rgba(88, 166, 255, 0.2);
  color: var(--accent-blue);
}

.alert-content {
  flex: 1;
  min-width: 0;
}

.alert-title {
  font-weight: 500;
  font-size: 13px;
  margin-bottom: 2px;
}

.alert-desc {
  color: var(--text-secondary);
  font-size: 12px;
}

.alert-time {
  color: var(--text-muted);
  font-size: 11px;
  white-space: nowrap;
}

.btn {
  padding: 4px 10px;
  border: 1px solid var(--border-color);
  border-radius: 6px;
  background: var(--bg-tertiary);
  color: var(--text-primary);
  cursor: pointer;
  font-size: 12px;
}

.btn:hover {
  background: var(--bg-secondary);
}

.empty {
  text-align: center;
  color: var(--text-muted);
  padding: 32px;
}
</style>
