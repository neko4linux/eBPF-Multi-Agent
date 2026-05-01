import axios from 'axios'
import type { Agent, Alert, Event, CausalLink, DashboardStats } from '@/types'

const api = axios.create({
  baseURL: '/api',
  timeout: 10000,
})

export function useApi() {
  // Agents
  async function getAgents(): Promise<Agent[]> {
    const { data } = await api.get<Agent[]>('/agents')
    return data
  }

  async function spawnAgent(type: string): Promise<Agent> {
    const { data } = await api.post<Agent>('/agents', { type })
    return data
  }

  async function stopAgent(id: string): Promise<void> {
    await api.delete(`/agents/${id}`)
  }

  // Events
  async function getEvents(limit = 50): Promise<Event[]> {
    const { data } = await api.get<Event[]>('/events', { params: { limit } })
    return data
  }

  // Alerts
  async function getAlerts(): Promise<Alert[]> {
    const { data } = await api.get<Alert[]>('/alerts')
    return data
  }

  async function acknowledgeAlert(id: string): Promise<void> {
    await api.patch(`/alerts/${id}`, { acknowledged: true })
  }

  // Causal Links
  async function getCausalLinks(): Promise<CausalLink[]> {
    const { data } = await api.get<CausalLink[]>('/causal-links')
    return data
  }

  // Stats
  async function getStats(): Promise<DashboardStats> {
    const { data } = await api.get<DashboardStats>('/stats')
    return data
  }

  // Scenarios
  async function triggerScenario(name: string): Promise<void> {
    await api.post('/scenarios', { name })
  }

  return {
    getAgents, spawnAgent, stopAgent,
    getEvents,
    getAlerts, acknowledgeAlert,
    getCausalLinks,
    getStats,
    triggerScenario,
  }
}
