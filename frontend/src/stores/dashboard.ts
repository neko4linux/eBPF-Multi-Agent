import { defineStore } from 'pinia'
import { ref } from 'vue'
import type { Agent, Alert, Event, CausalLink, DashboardStats, WSMessage } from '@/types'
import { useApi } from '@/composables/useApi'

export const useDashboardStore = defineStore('dashboard', () => {
  const api = useApi()

  const agents = ref<Agent[]>([])
  const alerts = ref<Alert[]>([])
  const events = ref<Event[]>([])
  const causalLinks = ref<CausalLink[]>([])
  const detectedAgents = ref<any[]>([])
  const stats = ref<DashboardStats>({
    total_agents: 0, running_agents: 0,
    total_events: 0, total_alerts: 0, critical_alerts: 0,
  })
  const loading = ref(false)

  async function fetchAll() {
    loading.value = true
    try {
      const [a, al, e, s] = await Promise.all([
        api.getAgents(),
        api.getAlerts(),
        api.getEvents(),
        api.getStats(),
      ])
      agents.value = a
      alerts.value = al
      events.value = e
      stats.value = s
    } catch (err) {
      console.error('[Dashboard] fetchAll error:', err)
    } finally {
      loading.value = false
    }
  }

  async function fetchDetected() {
    try {
      detectedAgents.value = await api.getDetectedAgents()
    } catch { /* ignore */ }
  }

  async function fetchCausalLinks() {
    causalLinks.value = await api.getCausalLinks()
  }

  function handleWSMessage(msg: WSMessage) {
    switch (msg.type) {
      case 'event':
        events.value.unshift(msg.data)
        if (events.value.length > 200) events.value.pop()
        stats.value.total_events++
        break
      case 'alert':
        alerts.value.unshift(msg.data)
        stats.value.total_alerts++
        if (msg.data.severity === 'critical' || msg.data.severity === 'CRITICAL') {
          stats.value.critical_alerts++
        }
        break
      case 'agent_update': {
        const idx = agents.value.findIndex(a => a.id === msg.data.id)
        if (idx >= 0) agents.value[idx] = msg.data
        else agents.value.push(msg.data)
        break
      }
      case 'agent_detected': {
        // 新 Agent 被 eBPF 检测到
        const exists = detectedAgents.value.find((a: any) => a.pid === msg.data.pid)
        if (!exists) {
          detectedAgents.value.unshift(msg.data)
        }
        break
      }
      case 'agent_anomaly': {
        // Agent 异常事件
        events.value.unshift({
          id: Date.now().toString(),
          agent_id: msg.data.agent?.type || 'unknown',
          event_type: 'ANOMALY',
          source: msg.data.agent?.name || 'unknown',
          target: msg.data.rule?.name || '',
          data: msg.data,
          timestamp: new Date().toISOString(),
        })
        stats.value.total_alerts++
        break
      }
      case 'stats':
        stats.value = msg.data
        break
      case 'clear':
        agents.value = []
        alerts.value = []
        events.value = []
        detectedAgents.value = []
        causalLinks.value = []
        stats.value = { total_agents: 0, running_agents: 0, total_events: 0, total_alerts: 0, critical_alerts: 0 }
        break
    }
  }

  async function spawnAgent(type: string) {
    await api.spawnAgent(type)
    await fetchAll()
  }

  async function triggerScenario(name: string) {
    await api.triggerScenario(name)
  }

  return {
    agents, alerts, events, causalLinks, detectedAgents, stats, loading,
    fetchAll, fetchDetected, fetchCausalLinks, handleWSMessage, spawnAgent, triggerScenario,
  }
})
