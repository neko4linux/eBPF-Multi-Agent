export interface Event {
  id: string
  agent_id: string
  event_type: string
  source: string
  target: string
  data: Record<string, any>
  timestamp: string
}

export type AlertSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info'

export interface Alert {
  id: string
  event_id: string
  severity: AlertSeverity
  title: string
  description: string
  acknowledged: boolean
  created_at: string
}

export type AgentStatus = 'running' | 'stopped' | 'error' | 'spawning'

export interface Agent {
  id: string
  name: string
  type: string
  status: AgentStatus
  metadata: Record<string, any>
  created_at: string
  updated_at: string
}

export interface CausalLink {
  id: string
  source_event_id: string
  target_event_id: string
  relationship: string
  confidence: number
  description: string
  created_at: string
}

export interface WSMessage {
  type: 'event' | 'alert' | 'agent_update' | 'stats'
  data: any
}

export interface DashboardStats {
  total_agents: number
  running_agents: number
  total_events: number
  total_alerts: number
  critical_alerts: number
}
