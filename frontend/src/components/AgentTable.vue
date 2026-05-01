<template>
  <div class="agent-table">
    <table>
      <thead>
        <tr>
          <th>名称</th>
          <th>类型</th>
          <th>状态</th>
          <th>创建时间</th>
          <th>操作</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="agent in agents" :key="agent.id">
          <td>{{ agent.name }}</td>
          <td><code>{{ agent.type }}</code></td>
          <td>
            <span class="badge" :class="'badge-' + agent.status">
              {{ statusLabel(agent.status) }}
            </span>
          </td>
          <td class="time">{{ formatTime(agent.created_at) }}</td>
          <td>
            <button
              v-if="agent.status === 'running'"
              class="btn btn-sm btn-danger"
              @click="$emit('stop', agent.id)"
            >停止</button>
          </td>
        </tr>
        <tr v-if="agents.length === 0">
          <td colspan="5" class="empty">暂无智能体</td>
        </tr>
      </tbody>
    </table>
  </div>
</template>

<script setup lang="ts">
import type { Agent, AgentStatus } from '@/types'

defineProps<{ agents: Agent[] }>()
defineEmits<{ stop: [id: string] }>()

const statusLabels: Record<AgentStatus, string> = {
  running: '运行中',
  stopped: '已停止',
  error: '错误',
  spawning: '启动中',
}

function statusLabel(s: AgentStatus) {
  return statusLabels[s] || s
}

function formatTime(t: string) {
  return new Date(t).toLocaleString('zh-CN')
}
</script>

<style scoped>
.agent-table {
  overflow-x: auto;
}

table {
  width: 100%;
  border-collapse: collapse;
}

th, td {
  padding: 10px 12px;
  text-align: left;
  border-bottom: 1px solid var(--border-color);
  font-size: 13px;
}

th {
  color: var(--text-secondary);
  font-weight: 500;
  font-size: 12px;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.time {
  color: var(--text-muted);
  font-size: 12px;
}

.empty {
  text-align: center;
  color: var(--text-muted);
  padding: 32px !important;
}

.badge {
  display: inline-block;
  padding: 2px 8px;
  border-radius: 12px;
  font-size: 11px;
  font-weight: 500;
}

.badge-running {
  background: rgba(63, 185, 80, 0.15);
  color: var(--accent-green);
}

.badge-stopped {
  background: rgba(110, 118, 129, 0.15);
  color: var(--text-muted);
}

.badge-error {
  background: rgba(248, 81, 73, 0.15);
  color: var(--accent-red);
}

.badge-spawning {
  background: rgba(210, 153, 34, 0.15);
  color: var(--accent-yellow);
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

.btn-danger {
  border-color: var(--accent-red);
  color: var(--accent-red);
}

.btn-danger:hover {
  background: rgba(248, 81, 73, 0.15);
}
</style>
