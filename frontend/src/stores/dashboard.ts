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
    } finally {
      loading.value = false
    }
  }

  async function fetchCausalLinks() {
    causalLinks.value = await api.getCausalLinks()
  }

  function handleWSMessage(msg: WSMessage) {
    switch (msg.type) {
      case 'event':
        events.value.unshift(msg.data)
        if (events.value.length > 200) events.value.pop()
        break
      case 'alert':
        alerts.value.unshift(msg.data)
        stats.value.total_alerts++
        if (msg.data.severity === 'critical') stats.value.critical_alerts++
        break
      case 'agent_update': {
        const idx = agents.value.findIndex(a => a.id === msg.data.id)
        if (idx >= 0) agents.value[idx] = msg.data
        else agents.value.push(msg.data)
        break
      }
      case 'stats':
        stats.value = msg.data
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
    agents, alerts, events, causalLinks, stats, loading,
    fetchAll, fetchCausalLinks, handleWSMessage, spawnAgent, triggerScenario,
  }
})
