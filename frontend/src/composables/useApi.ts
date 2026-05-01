import axios from 'axios'
import type { Agent, Alert, Event, CausalLink, DashboardStats } from '@/types'

const api = axios.create({
  baseURL: '/api',
  timeout: 10000,
})

// ─── Agent 类型 ───
export interface AgentProfile {
  type: string
  name: string
  description: string
  process_names: string[]
  cmdline_patterns: string[]
  api_domains: string[]
  api_tokens: string[]
  ssl_hook_target: string
  dangerous_ops: string[]
  risk_level: string
}

export interface DetectedAgent {
  pid: number
  name: string
  type: string
  profile: AgentProfile
  first_seen: string
  last_seen: string
  event_count: number
  alert_count: number
  risk_score: number
}

export interface AnomalyRule {
  name: string
  agent_type: string
  event_type: string
  condition: string
  severity: string
  description: string
  keywords: string[]
}

export interface AgentTypeInfo {
  type: string
  name: string
  icon: string
  risk: string
}

export function useApi() {
  // ─── Generic GET ───
  async function get<T = any>(url: string): Promise<T> {
    const { data } = await api.get<T>(url)
    return data
  }

  // Agents
  async function getAgents(): Promise<Agent[]> {
    const { data } = await api.get<Agent[]>('/agents')
    return data
  }

  async function spawnAgent(type: string): Promise<Agent> {
    const { data } = await api.post<Agent>(`/spawn/${type}`)
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
    await api.post(`/trigger/${name}`)
  }

  // ─── Agent Integration ───
  async function getAgentProfiles(): Promise<AgentProfile[]> {
    const { data } = await api.get<AgentProfile[]>('/agents/profiles')
    return data
  }

  async function getDetectedAgents(): Promise<DetectedAgent[]> {
    const { data } = await api.get<DetectedAgent[]>('/agents/detected')
    return data
  }

  async function getAnomalyRules(): Promise<AnomalyRule[]> {
    const { data } = await api.get<AnomalyRule[]>('/agents/rules')
    return data
  }

  async function getAgentTypes(): Promise<AgentTypeInfo[]> {
    const { data } = await api.get<AgentTypeInfo[]>('/agents/types')
    return data
  }

  async function manualDetect(params: {
    pid?: number
    comm: string
    cmdline: string
    event_type?: string
    detail?: string
  }): Promise<any> {
    const { data } = await api.post('/agents/detect', params)
    return data
  }

  return {
    get,
    getAgents, spawnAgent, stopAgent,
    getEvents,
    getAlerts, acknowledgeAlert,
    getCausalLinks,
    getStats,
    triggerScenario,
    getAgentProfiles, getDetectedAgents, getAnomalyRules,
    getAgentTypes, manualDetect,
  }
}
