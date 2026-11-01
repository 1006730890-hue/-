import axios from 'axios'
const api = axios.create({ baseURL: '/', timeout: 15000 })
api.interceptors.request.use(config => {
  const token = localStorage.getItem('bank-admin-token')
  if (token) config.headers.Authorization = `Bearer ${token}`
  return config
})
export const accounts = () => api.get('/api/admin/auth/demo-accounts').then(r => r.data)
export const login = login_name => api.post('/api/admin/auth/demo-login', { login_name }).then(r => r.data)
export const me = () => api.get('/api/admin/me').then(r => r.data)
export const dashboard = () => api.get('/api/admin/dashboard').then(r => r.data)
export const reviews = () => api.get('/api/admin/reviews').then(r => r.data)
export const claimReview = id => api.post(`/api/admin/reviews/${id}/claim`).then(r => r.data)
export const risks = () => api.get('/api/admin/risk-events').then(r => r.data)
export const approvals = () => api.get('/api/admin/approvals').then(r => r.data)
export const createApproval = body => api.post('/api/admin/approvals', body).then(r => r.data)
export const decideApproval = (id, body) => api.post(`/api/admin/approvals/${id}/decision`, body).then(r => r.data)
export const audit = () => api.get('/api/admin/audit').then(r => r.data)
export const verifyAudit = () => api.get('/api/admin/audit/verify').then(r => r.data)
