<template>
  <div v-if="!accessToken" class="login-shell">
    <el-card class="login-card">
      <h2>多多银行智能体</h2>
      <p class="muted">登录后查询账户或办理业务，每次操作均经过鉴衡安全校验。</p>
      <el-input v-model="loginName" placeholder="客户登录名" style="margin:10px 0" />
      <el-input v-model="loginPassword" type="password" show-password placeholder="客户密码" @keyup.enter="signIn" />
      <el-button type="primary" :loading="loginBusy" @click="signIn" style="margin-top:16px;width:100%">登录</el-button>
      <p v-if="loginError" class="login-error">{{ loginError }}</p>
      <p class="muted">首次启动的本机凭据保存在 backend/data/initial-customer-access.txt。</p>
    </el-card>
  </div>
  <div v-else class="layout">
    <header class="topbar">
      <div class="brand">
        <span class="logo">多</span>
        <div>
          <div class="title">多多银行智能体</div>
          <div class="sub">说一句话，就能办业务</div>
        </div>
      </div>
      <el-button link style="color:#fff;margin-left:auto;margin-right:20px" @click="signOut">退出登录</el-button>
      <el-tag :type="llmOnline ? 'success' : 'warning'" effect="dark">
        {{ llmOnline ? '智能业务服务在线' : '基础业务服务在线' }}
      </el-tag>
    </header>

    <div class="body">
      <aside class="side">
        <el-card shadow="never" class="safety-card">
          <template #header><strong>鉴衡 · 安全防护</strong></template>
          <div>本次判定：{{ ({ allow: '放行', ask: '等待确认', deny: '已阻断', cancelled:'已取消' })[securityState?.decision] || '已启用' }}</div>
          <div class="muted">输入检测 → 授权校验 → 确认执行 → 结果隔离</div>
          <div class="muted">检测：{{ securityState?.input_detector === 'external_configured' ? '智能检测与业务规则协同保护' : '业务规则保护' }}</div>
          <div class="muted">账务在本系统持久化，未连接银行清算网络。</div>
          <div v-if="securityState?.mfa_delivery === 'local_outbox'" class="muted">高风险操作需要额外验证码验证。</div>
          <el-button size="small" @click="showAudit" style="margin-top:8px">查看安全审计</el-button>
        </el-card>
        <el-card shadow="never" class="balance-card">
          <div class="label">账户余额（本地账本，元）</div>
          <div class="balance">{{ ov.balance?.toFixed(2) || '--' }}</div>
          <div class="acc">{{ ov.account_no }}</div>
        </el-card>

        <el-card shadow="never">
          <template #header><span>我的卡片</span></template>
          <div v-for="c in ov.cards" :key="c.id" class="card-row">
            <span>{{ c.card_type }} · {{ c.card_no }}</span>
            <el-tag size="small" :type="statusType(c.status)">{{ statusText(c.status) }}</el-tag>
          </div>
        </el-card>

        <el-card shadow="never">
          <template #header><span>自动续费</span></template>
          <div v-for="s in ov.subscriptions" :key="s.id" class="sub-row">
            <span>{{ s.name }}</span><span>¥{{ s.amount }}/{{ s.cycle }}</span>
          </div>
        </el-card>

        <el-card shadow="never">
          <template #header><span>目标任务</span></template>
          <div v-if="!ov.goals?.length" class="muted">暂无</div>
          <div v-for="g in ov.goals" :key="g.id" class="goal-row">
            <div>{{ g.description }}</div>
            <div class="muted">截止 {{ g.due_date }}</div>
          </div>
        </el-card>
      </aside>

      <main class="chat">
        <div class="messages" ref="msgBox">
          <div v-for="(m, i) in messages" :key="i" class="msg" :class="m.role">
            <div class="bubble">
              <div v-if="m.role === 'assistant'" class="avatar">多</div>
              <div class="bubble-text">
                <div v-if="m.text" class="reply-text">{{ m.text }}</div>
                <el-card v-if="m.confirm" shadow="hover" class="confirm-card">
                  <div class="confirm-head">
                    <el-tag :type="m.confirm.risk_level === 'red' ? 'danger' : 'warning'" effect="dark">
                      {{ m.confirm.risk_level === 'red' ? '高风险 · 需验证' : '中风险 · 请确认' }}
                    </el-tag>
                    <span class="tool-name">{{ toolLabel(m.confirm.tool) }}</span>
                  </div>
                  <div class="args">
                    <div v-for="(v, k) in m.confirm.args" :key="k">
                      <span class="arg-k">{{ argLabel(k) }}</span>：{{ argValue(k, v) }}
                    </div>
                  </div>
                  <template v-if="m.confirm.mfa_required && !m.done">
                    <el-input v-model="m.mfa" :placeholder="m.confirm.mfa_method === 'totp' ? '请输入验证器动态码' : '请输入验证码'" maxlength="6" style="width:200px;margin:8px 0" />
                    <div v-if="m.confirm.mfa_method === 'local_outbox'" class="muted">请使用本机验证渠道收到的验证码。</div>
                    <div v-if="m.confirm.demo_mfa_code" class="muted">演示验证码：{{ m.confirm.demo_mfa_code }}</div>
                  </template>
                  <div v-if="!m.done" class="confirm-btns">
                    <el-button type="primary" size="small" @click="doConfirm(m, true)">确认执行</el-button>
                    <el-button size="small" @click="doConfirm(m, false)">取消</el-button>
                  </div>
                  <div v-else class="done">{{ m.resultText }}<div v-if="m.receipt">交易流水号：{{ m.receipt }}</div></div>
                </el-card>
              </div>
            </div>
          </div>
          <div v-if="loading" class="msg assistant"><div class="bubble"><div class="typing">多多正在思考…</div></div></div>
        </div>

        <div class="input-bar">
          <el-input v-model="input" placeholder="试试：帮我看看这个月花了多少 / 给张三转500元 / 我老婆快生日了"
                    @keyup.enter="send" />
          <el-button type="primary" :loading="loading" @click="send">发送</el-button>
        </div>
      </main>
    </div>
    <el-drawer v-model="auditVisible" title="安全审计与执行证据" size="520px">
      <el-alert v-if="securityState?.audit_chain" :closable="false" style="margin-bottom:20px"
        :type="securityState.audit_chain.valid ? 'success' : 'error'"
        :title="securityState.audit_chain.valid ? '审计记录完整性校验通过' : '审计记录完整性校验未通过'"
        :description="'已核对 ' + securityState.audit_chain.checked + ' 条记录；业务参数、确认申请和执行结果可关联追溯。'" />
      <el-timeline>
        <el-timeline-item v-for="(event, i) in securityEvents" :key="i" :timestamp="event.at || ''">
          <strong>{{ event.title || event.stage }}</strong>
          <div class="event-detail">{{ event.summary || '' }}</div>
          <el-tag v-if="event.verdict" size="small" :type="event.verdict === '已阻断' ? 'danger' : 'success'">{{ event.verdict }}</el-tag>
        </el-timeline-item>
      </el-timeline>
    </el-drawer>
  </div>
</template>

<script setup>
import { ref, nextTick, onMounted } from 'vue'
import { chat, confirmAction, overview, health, safetyStatus, securityRun, auditLogs, login, logout, resetConversation } from './api'

const accessToken = ref(sessionStorage.getItem('bank-duplex-token') || '')
const loginName = ref('张伟')
const loginPassword = ref('')
const loginBusy = ref(false)
const loginError = ref('')
async function signIn() {
  loginBusy.value = true
  loginError.value = ''
  try {
    const result = await login(loginName.value,loginPassword.value)
    resetConversation()
    messages.value = []
    accessToken.value = result.token
    sessionStorage.setItem('bank-duplex-token',result.token)
    loginPassword.value = ''
    await loadWorkspace()
  } catch (e) {
    loginError.value = e.response?.data?.detail || '登录暂不可用，请稍后重试。'
  } finally { loginBusy.value = false }
}
async function signOut() {
  try { await logout() } catch (e) {}
  sessionStorage.removeItem('bank-duplex-token')
  resetConversation()
  accessToken.value = ''
  messages.value = []
}
window.addEventListener('bank-auth-expired',() => {
  accessToken.value = ''
  sessionStorage.removeItem('bank-duplex-token')
})
const messages = ref([])
const input = ref('')
const loading = ref(false)
const llmOnline = ref(false)
const securityState = ref(null)
const securityEvents = ref([])
const auditVisible = ref(false)
const msgBox = ref(null)
const ov = ref({})

const toolLabel = (t) => ({
  transfer: '转账', cancel_subscription: '取消订阅', report_card_loss: '卡片挂失',
  toggle_card_freeze: '卡片冻结', create_goal: '创建目标', purchase_wealth: '理财申购',
  redeem_wealth: '理财赎回', get_balance:'账户余额查询', monthly_bill:'月度账单查询',
  list_transactions:'交易流水查询', list_cards:'查询卡片',list_subscriptions:'查询自动续费',
  spending_report:'消费分析',find_recipients:'查询收款人',list_goals:'查询目标任务',
  detect_anomaly:'异常交易检查',list_wealth_products:'理财产品查询',get_holdings:'持仓查询',
  compare_products:'理财产品比较',recommend_wealth:'理财匹配',adjust_credit_limit:'调整卡片额度',
  schedule_transfer:'预约转账',create_aa_request:'分摊收款'
}[t] || '业务处理')
const argLabel = (k) => ({
  to_name: '收款人', to_phone: '手机号', amount: '金额(元)', note: '备注',
  name: '订阅', card_id: '卡片编号', action: '操作', new_limit: '新额度',
  description: '目标', due_date: '截止日', product_name: '产品'
}[k] || k)
const argValue = (k, v) => k === 'action' ? ({freeze:'冻结', unfreeze:'解冻'}[v] || v) : v
const statusType = (s) => ({ normal: 'success', frozen: 'warning', reported: 'danger' }[s] || 'info')
const statusText = (s) => ({ normal: '正常', frozen: '已冻结', reported: '已挂失' }[s] || s)

async function refresh() {
  ov.value = await overview()
}

async function send() {
  const text = input.value.trim()
  if (!text || loading.value) return
  input.value = ''
  messages.value.push({ role: 'user', text })
  loading.value = true
  try {
    const res = await chat(text)
    pushAssistant(res)
    if (res.security?.run_id) { securityEvents.value = (await securityRun(res.security.run_id)).evidence }
    await refresh()
  } catch (e) {
    messages.value.push({ role: 'assistant', text: '服务暂不可用：' + e.message })
  } finally {
    loading.value = false
    scrollDown()
  }
}

function pushAssistant(res) {
  if (res.security) securityState.value = { ...securityState.value, ...res.security }
  if (res.needs_confirm) {
    messages.value.push({ role: 'assistant', text: res.reply, confirm: res.confirm, mfa: '', done: false, resultText: '' })
  } else {
    messages.value.push({ role: 'assistant', text: res.reply })
  }
  scrollDown()
}

async function doConfirm(m, approved) {
  if (m.busy || m.done) return
  m.busy = true
  try {
    const res = await confirmAction(m.confirm.action_id, approved, approved ? m.mfa : null)
    m.resultText = res.reply
    m.receipt = res.result?.transaction_id
    m.done = !res.mfa_retry
    if (res.executed) securityState.value = { ...securityState.value, decision:'allow' }
    else if (res.rejected) securityState.value = { ...securityState.value, decision:'cancelled' }
    if (res.mfa_retry) m.text = res.reply + ' 剩余尝试次数：' + res.attempts_remaining
    await refresh()
  } catch (e) {
    m.text = '确认请求失败，请稍后核对状态：' + e.message
  } finally {
    m.busy = false
    scrollDown()
  }
}

async function showAudit() {
  const labels = {login:'客户登录',input_screen:'用户输入安全检测',pending_confirm:'生成业务确认申请',
    execute_action:'确认后执行业务',confirm_action:'客户确认',transfer:'转账入账',get_balance:'账户余额查询',
    get_transactions:'交易流水查询',get_bill:'账单查询',toggle_card_freeze:'卡片冻结或解冻',
    cancel_subscription:'订阅管理',list_subscriptions:'查询自动续费',list_cards:'查询卡片',
    output_isolation:'工具结果安全隔离',tool_result:'业务结果核验',memory_recall:'记忆可信度检查',
    action_validation:'业务动作授权检查',get_spending_report:'消费分析',get_monthly_bill:'月度账单查询',
    model_verdict:'模型业务校验',plan:'生成执行计划',dynamic_validation:'逐步动作核验',
    authorization:'业务授权判定',result_isolation:'业务结果安全隔离',memory_read:'历史记忆安全检查',
    privilege_cache:'工具权限核验',turn_failed:'本次请求未完成',confirmation_rejected:'客户取消申请'}
  const parse = value => { try { return typeof value === 'string' ? JSON.parse(value) : (value || {}) } catch { return {} } }
  const [auditData, latestSafety] = await Promise.all([auditLogs(), safetyStatus()])
  securityState.value = { ...securityState.value, ...latestSafety }
  securityEvents.value = auditData.logs.map(x => {
    const p = parse(x.params), r = parse(x.result)
    const detail = p.args || p
    const blocked = r.decision === 'deny' || r.blocked === true
    const title = labels[x.action] || toolLabel(x.action) || '安全处理记录'
    const parts = []
    if (p.tool) parts.push('业务：' + toolLabel(p.tool))
    if (detail.to_name) parts.push('收款人：' + detail.to_name)
    if (detail.amount != null) parts.push('金额：' + detail.amount + ' 元')
    if (r.transaction_id) parts.push('流水号：' + r.transaction_id)
    if (r.action_id) parts.push('确认申请：' + r.action_id)
    if (r.reply) parts.push(r.reply)
    if (x.action === 'result_isolation' || x.action === 'memory_read') parts.push(r.quarantined ? '已隔离可疑内容' : r.detected ? '可疑字段已处理' : '检查通过')
    if (x.action === 'dynamic_validation' && r.decision === 'ask') parts.push('需要客户确认后执行')
    if (x.action === 'plan') parts.push('已形成业务办理步骤')
    if (x.action === 'model_verdict') parts.push(({
      plan:'生成业务步骤',parameter_constraints:'核对参数条件',privilege_classification:'核对工具权限',
      intent_alignment:'检查动作与客户意愿是否一致',safe_write_review:'检查资金操作参数来源'
    })[r.purpose] || '检查本次业务请求')
    if (r.decision === 'allow') parts.push('安全检查通过')
    if (blocked) parts.push('安全检查阻断本次请求')
    if (r.ok === true) parts.push('业务处理成功')
    if (r.balance != null) parts.push('余额：' + r.balance + ' 元')
    return { title, summary: parts.join('；'), verdict: blocked ? '已阻断' : r.ok === true || r.decision === 'allow' ? '已通过' : '', at: new Date(x.ts).toLocaleString('zh-CN',{hour12:false}) }
  })
  auditVisible.value = true
}

function scrollDown() {
  nextTick(() => { if (msgBox.value) msgBox.value.scrollTop = msgBox.value.scrollHeight })
}

async function loadWorkspace() {
  try { llmOnline.value = (await health()).llm_online } catch (e) {}
  try { securityState.value = await safetyStatus() } catch (e) {}
  refresh()
  if (!messages.value.length) messages.value.push({ role: 'assistant', text: '您好，我是多多。可以查余额、看账单、分析消费、管订阅、买理财、转账和管卡片。' })
}
onMounted(() => { if (accessToken.value) loadWorkspace() })
</script>

<style>
* { box-sizing: border-box; }
body { margin: 0; font-family: 'PingFang SC', 'Microsoft YaHei', sans-serif; background: #f0f2f5; }
.layout { height: 100vh; display: flex; flex-direction: column; }
.topbar { height: 60px; background: #1f4e9c; color: #fff; display: flex; align-items: center;
  justify-content: space-between; padding: 0 24px; }
.brand { display: flex; align-items: center; gap: 12px; }
.logo { width: 38px; height: 38px; border-radius: 8px; background: #fff; color: #1f4e9c;
  display: flex; align-items: center; justify-content: center; font-weight: bold; font-size: 20px; }
.title { font-size: 17px; font-weight: 600; }
.sub { font-size: 12px; opacity: .8; }
.body { flex: 1; display: flex; overflow: hidden; }
.side { width: 300px; padding: 16px; overflow-y: auto; display: flex; flex-direction: column; gap: 12px; }
.balance-card .label { font-size: 13px; color: #666; }
.balance-card .balance { font-size: 28px; font-weight: 700; color: #1f4e9c; margin: 4px 0; }
.acc { font-size: 12px; color: #999; }
.card-row, .sub-row, .goal-row { display: flex; justify-content: space-between; font-size: 13px; padding: 4px 0; }
.muted { color: #999; font-size: 12px; }
.chat { flex: 1; display: flex; flex-direction: column; background: #fff; }
.messages { flex: 1; overflow-y: auto; padding: 24px; }
.msg { margin-bottom: 16px; display: flex; }
.msg.user { justify-content: flex-end; }
.bubble { display: flex; gap: 8px; max-width: 70%; }
.msg.user .bubble { flex-direction: row-reverse; }
.avatar { width: 34px; height: 34px; border-radius: 50%; background: #1f4e9c; color: #fff;
  display: flex; align-items: center; justify-content: center; flex-shrink: 0; }
.bubble-text { background: #f4f6fa; padding: 10px 14px; border-radius: 10px; line-height: 1.6; }
.msg.user .bubble-text { background: #1f4e9c; color: #fff; }
.confirm-card { margin-top: 8px; min-width: 320px; }
.confirm-head { display: flex; align-items: center; gap: 8px; margin-bottom: 8px; }
.tool-name { font-weight: 600; }
.args { font-size: 13px; color: #333; line-height: 1.8; }
.arg-k { color: #888; }
.confirm-btns { margin-top: 10px; }
.done { margin-top: 8px; color: #1f4e9c; font-size: 13px; }
.mfa-code-hint { color: #e6a23c; font-size: 12px; }
.typing { color: #999; font-size: 13px; }
.input-bar { display: flex; gap: 10px; padding: 16px; border-top: 1px solid #eee; }
</style>

<style>.event-detail { white-space:pre-wrap;word-break:break-all;font-size:12px;color:#516078; }.safety-card{border-left:3px solid #2c8b67;}.safety-card .muted{margin-top:5px;}</style>

<style>.login-shell{height:100vh;display:grid;place-items:center;background:#edf2f9}.login-card{width:440px;max-width:94vw;padding:18px}.login-error{color:#b63838;font-size:13px}</style>

<style>
.side > .el-card { flex-shrink: 0; }
.chat, .bubble-text { min-width: 0; }
.bubble-text { overflow-wrap: anywhere; }
.reply-text { white-space: pre-wrap; }
@media (max-width: 760px) {
  .topbar { height: 64px; min-height: 64px; padding: 8px 12px; gap: 6px; }
  .brand { gap: 6px; min-width: 0; flex: 1; }
  .logo { width: 30px; height: 32px; flex-shrink: 0; font-size: 15px; }
  .title { font-size: 13px; line-height: 18px; }
  .sub { display: none; }
  .topbar > .el-button { margin: 0 !important; font-size: 11px; }
  .topbar > .el-tag { max-width: 100px; overflow: hidden; font-size: 10px; padding: 0 5px; }
  .body { flex-direction: column; }
  .side { width: 100%; padding: 10px; display: grid; grid-template-columns: 1fr 1fr; gap: 8px; overflow: visible; flex-shrink: 0; }
  .side > .el-card:not(.safety-card):not(.balance-card) { display: none; }
  .side .el-card__header { padding: 10px; font-size: 12px; }
  .side .el-card__body { padding: 10px; }
  .safety-card { font-size: 12px; }
  .safety-card .muted { display: none; }
  .balance-card .label { font-size: 11px; }
  .balance-card .balance { font-size: 21px; }
  .balance-card .acc { font-size: 10px; }
  .chat { flex: 1; min-height: 0; }
  .messages { padding: 12px; }
  .bubble { max-width: 98%; gap: 6px; }
  .bubble-text { padding: 10px; font-size: 14px; }
  .avatar { width: 28px; height: 28px; font-size: 13px; }
  .confirm-card { min-width: 0; width: 100%; }
  .input-bar { gap: 8px; padding: 10px; }
  .input-bar .el-input { min-width: 0; }
}
</style>
