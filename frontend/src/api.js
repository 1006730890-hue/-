import axios from 'axios'
const api = axios.create({ baseURL: '/', timeout: 300000 })
api.interceptors.request.use(config => {
  const token = sessionStorage.getItem('bank-duplex-token')
  if (token) config.headers.Authorization = 'Bearer ' + token
  return config
})
api.interceptors.response.use(r => r, error => {
  if (error.response?.status === 401) window.dispatchEvent(new Event('bank-auth-expired'))
  return Promise.reject(error)
})
export const login = (login_name,password) => api.post('/api/auth/login',{login_name,password}).then(r=>r.data)
export const logout = () => api.post('/api/auth/logout').then(r=>r.data)
let conversationId = sessionStorage.getItem('bank-duplex-conversation') || null
export const resetConversation = () => { conversationId = null; sessionStorage.removeItem('bank-duplex-conversation') }
export const chat = async (message) => {
  const { data } = await api.post('/api/chat', { message,  conversation_id:conversationId })
  conversationId = data.conversation_id || conversationId
  if (conversationId) sessionStorage.setItem('bank-duplex-conversation',conversationId)
  return data
}
export const confirmAction = (action_id,approved,mfa_code) => api.post('/api/confirm',
  {action_id,approved,mfa_code,conversation_id:conversationId}).then(r=>r.data)
export const overview = () => api.get('/api/overview',{}).then(r=>r.data)
export const health = () => api.get('/health').then(r=>r.data)
export const safetyStatus = () => api.get('/api/security/status').then(r=>r.data)
export const securityRun = (id) => api.get('/api/security/runs/'+id).then(r=>r.data)
export const auditLogs = () => api.get('/api/audit').then(r=>r.data)
