import { ref, onUnmounted } from 'vue'
import type { WSMessage } from '@/types'

export function useWebSocket(url: string) {
  const data = ref<WSMessage | null>(null)
  const isConnected = ref(false)
  const reconnectAttempts = ref(0)
  let ws: WebSocket | null = null
  let reconnectTimer: ReturnType<typeof setTimeout> | null = null
  const maxReconnectAttempts = 10

  function connect() {
    const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:'
    const wsUrl = `${protocol}//${location.host}${url}`
    ws = new WebSocket(wsUrl)

    ws.onopen = () => {
      isConnected.value = true
      reconnectAttempts.value = 0
    }

    ws.onmessage = (event) => {
      try {
        data.value = JSON.parse(event.data) as WSMessage
      } catch {
        console.warn('Failed to parse WS message:', event.data)
      }
    }

    ws.onclose = () => {
      isConnected.value = false
      scheduleReconnect()
    }

    ws.onerror = () => {
      ws?.close()
    }
  }

  function scheduleReconnect() {
    if (reconnectAttempts.value >= maxReconnectAttempts) return
    const delay = Math.min(1000 * 2 ** reconnectAttempts.value, 30000)
    reconnectTimer = setTimeout(() => {
      reconnectAttempts.value++
      connect()
    }, delay)
  }

  function disconnect() {
    if (reconnectTimer) clearTimeout(reconnectTimer)
    ws?.close()
    ws = null
  }

  connect()

  onUnmounted(() => disconnect())

  return { data, isConnected, reconnectAttempts, disconnect }
}
