<template>
  <div class="control-panel">
    <div class="panel-section">
      <h3 class="section-title">生成智能体</h3>
      <div class="button-group">
        <button class="btn" @click="$emit('spawn', 'network')">🌐 网络监控</button>
        <button class="btn" @click="$emit('spawn', 'process')">⚙️ 进程监控</button>
        <button class="btn" @click="$emit('spawn', 'security')">🛡️ 安全监控</button>
        <button class="btn" @click="$emit('spawn', 'filesystem')">📁 文件监控</button>
      </div>
    </div>
    <div class="panel-section">
      <h3 class="section-title">触发场景</h3>
      <div class="button-group">
        <button class="btn btn-warn" @click="$emit('scenario', 'port-scan')">🔍 端口扫描</button>
        <button class="btn btn-warn" @click="$emit('scenario', 'privilege-escalation')">⬆️ 提权攻击</button>
        <button class="btn btn-warn" @click="$emit('scenario', 'data-exfiltration')">📤 数据泄露</button>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
defineEmits<{
  spawn: [type: string]
  scenario: [name: string]
}>()
</script>

<style scoped>
.control-panel {
  display: flex;
  gap: 24px;
  flex-wrap: wrap;
}

.panel-section {
  flex: 1;
  min-width: 250px;
}

.section-title {
  font-size: 13px;
  font-weight: 600;
  color: var(--text-secondary);
  margin-bottom: 12px;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.button-group {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}

.btn {
  padding: 8px 16px;
  border: 1px solid var(--border-color);
  border-radius: 6px;
  background: var(--bg-secondary);
  color: var(--text-primary);
  cursor: pointer;
  font-size: 13px;
  transition: all 0.15s ease;
}

.btn:hover {
  background: var(--bg-tertiary);
  border-color: var(--accent-blue);
}

.btn-warn:hover {
  border-color: var(--accent-yellow);
}
</style>
