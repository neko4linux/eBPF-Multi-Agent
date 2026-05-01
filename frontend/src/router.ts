import { createRouter, createWebHistory } from 'vue-router'

const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', name: 'dashboard', component: () => import('./views/Dashboard.vue') },
    { path: '/agents', name: 'agents', component: () => import('./views/Agents.vue') },
    { path: '/alerts', name: 'alerts', component: () => import('./views/Alerts.vue') },
    { path: '/causal-links', name: 'causal-links', component: () => import('./views/CausalLinks.vue') },
  ],
})

export default router
