<template>
  <div class="event-log">
    <div v-for="event in events" :key="event.id" class="event-item">
      <span class="event-type">{{ event.event_type }}</span>
      <span class="event-source">{{ event.source }}</span>
      <span class="event-arrow">→</span>
      <span class="event-target">{{ event.target }}</span>
      <span class="event-time">{{ formatTime(event.timestamp) }}</span>
    </div>
    <div v-if="events.length === 0" class="empty">暂无事件</div>
  </div>
</template>

<script setup lang="ts">
import type { Event } from '@/types'

defineProps<{ events: Event[] }>()

function formatTime(t: string) {
  return new Date(t).toLocaleTimeString('zh-CN')
}
</script>

<style scoped>
.event-log {
  max-height: 400px;
  overflow-y: auto;
}

.event-item {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px 12px;
  border-bottom: 1px solid var(--border-color);
  font-size: 13px;
  font-family: 'SF Mono', 'Fira Code', monospace;
}

.event-item:hover {
  background: var(--bg-tertiary);
}

.event-type {
  background: rgba(88, 166, 255, 0.15);
  color: var(--accent-blue);
  padding: 1px 6px;
  border-radius: 4px;
  font-size: 11px;
  font-weight: 600;
  min-width: 90px;
  text-align: center;
}

.event-source, .event-target {
  color: var(--accent-purple);
  font-size: 12px;
}

.event-arrow {
  color: var(--text-muted);
}

.event-time {
  margin-left: auto;
  color: var(--text-muted);
  font-size: 11px;
}

.empty {
  text-align: center;
  color: var(--text-muted);
  padding: 32px;
}
</style>
