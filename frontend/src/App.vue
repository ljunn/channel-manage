<script setup>
import { computed, onMounted, reactive, ref, watch } from 'vue'
import {
  Activity, AlertTriangle, ArrowRight, BarChart3, Bot, Check, ChevronRight, CircleDollarSign, ClipboardList,
  Database, FileClock, Gauge, History, KeyRound, LogOut, Menu, Network, Pause, Pencil, Play, Plus,
  RefreshCw, Search, Settings, ShieldCheck, SlidersHorizontal, Trash2, UserCog, Workflow, X,
} from '@lucide/vue'
import ModalShell from './components/ModalShell.vue'
import StateBlock from './components/StateBlock.vue'

const tokenKey = 'channel_manage_token'
const token = ref(sessionStorage.getItem(tokenKey) || '')
const operator = ref(null)
const route = ref(location.hash.slice(1) || '/overview')
const mobileOpen = ref(false)
const loading = ref(false)
const notice = ref('')
const error = ref('')
const modal = ref('')
const search = ref('')
const appVersion = ref('')
const data = reactive({ summary: {}, sources: [], targets: [], channels: [], managed: [], market: [], history: [], policies: [], actions: [], events: [], audit: [], settings: {}, notifications: [] })
const sourceDetail = ref(null)
const selectedSource = ref('')
const targetGroups = ref([])
const form = reactive({})

const nav = [
  { label: '经营视图', items: [['/overview','运营总览',Gauge],['/market','市场大盘',CircleDollarSign],['/sources','数据源',Database]] },
  { label: '生产调度', items: [['/scheduling','调度运行',Workflow],['/channels','渠道雷达',Activity],['/managed','托管账号',Bot],['/targets','目标节点',Network],['/policies','策略配置',SlidersHorizontal]] },
  { label: '审计与系统', items: [['/events','事件中心',AlertTriangle],['/audit','审计日志',FileClock],['/settings','系统设置',Settings]] },
]
const routeNames = Object.fromEntries(nav.flatMap(group => group.items.map(([path,label]) => [path,label])))
const pageTitle = computed(() => routeNames[route.value] || '渠道管家')
const pageIcon = computed(() => nav.flatMap(group => group.items).find(([path]) => path === route.value)?.[2] || Gauge)
const searchableRoutes = new Set(['/market','/sources','/scheduling','/channels','/managed','/targets','/policies','/events','/audit'])
const showSearch = computed(() => searchableRoutes.has(route.value))
const writableTargets = computed(() => data.targets.filter(item => item.writeEnabled))
const selectedSourceGroups = computed(() => (sourceDetail.value?.groups||[]).filter(group => form.sourceGroupIDs?.includes(group.id)))
const selectedTargetGroups = computed(() => targetGroups.value.filter(group => form.targetGroupIDs?.includes(group.id)))
const selectedTarget = computed(() => writableTargets.value.find(item => item.id===form.targetID))
const filtered = items => !search.value ? items : items.filter(item => JSON.stringify(item).toLowerCase().includes(search.value.toLowerCase()))

window.addEventListener('hashchange', () => { route.value = location.hash.slice(1) || '/overview'; mobileOpen.value = false })
watch(route, () => { search.value=''; clearMessages(); if(token.value) void loadPage() })
onMounted(async () => { void loadVersion(); if (token.value) { try { operator.value=await api('/auth/me'); await loadPage() } catch {} } else route.value='/login' })

async function loadVersion(){
  try{const response=await fetch('/health',{headers:{accept:'application/json'}});if(response.ok)appVersion.value=(await response.json()).version||''}catch{}
}

async function api(path, init={}) {
  const headers = new Headers(init.headers || {})
  headers.set('accept','application/json')
  if (init.body) headers.set('content-type','application/json')
  if (token.value) headers.set('authorization',`Bearer ${token.value}`)
  let response
  try { response = await fetch(`/api${path}`, { ...init, headers, signal: AbortSignal.timeout(30000) }) }
  catch (reason) { throw new Error(reason?.name === 'TimeoutError' ? '请求超时' : '无法连接服务') }
  const payload = await response.json().catch(() => ({}))
  if (!response.ok) { if(response.status===401 && path!='/auth/login') logout(false); throw new Error(payload.error?.message || `请求失败 (${response.status})`) }
  return payload.data
}
function body(value){ return JSON.stringify(value) }
function clearMessages(){ notice.value=''; error.value='' }
function showError(reason){ error.value=reason instanceof Error ? reason.message : '操作失败' }
function go(path){ location.hash=path }
function logout(call=true){ if(call&&token.value) void api('/auth/logout',{method:'POST'}).catch(()=>{});token.value='';operator.value=null;sessionStorage.removeItem(tokenKey);go('/login') }

async function login(event){
  const values=Object.fromEntries(new FormData(event.currentTarget));loading.value=true;clearMessages()
  try{const result=await api('/auth/login',{method:'POST',body:body(values)});token.value=result.access_token;operator.value=result.operator;sessionStorage.setItem(tokenKey,token.value);go('/overview');await loadPage()}
  catch(reason){showError(reason)}finally{loading.value=false}
}

async function loadPage(){
  loading.value=true;clearMessages()
  try{
    const path=route.value
    if(path==='/overview') data.summary=await api('/dashboard/summary')
    else if(path==='/sources') data.sources=await api('/sources')
    else if(path==='/targets') data.targets=await api('/targets')
    else if(path==='/channels') data.channels=await api('/channels')
    else if(path==='/managed') data.managed=await api('/managed-accounts')
    else if(path==='/market') [data.market,data.history]=await Promise.all([api('/market/groups'),api('/market/price-history')])
    else if(path==='/policies') data.policies=await api('/policies')
    else if(path==='/scheduling') data.actions=await api('/action-intents')
    else if(path==='/events') data.events=await api('/events')
    else if(path==='/audit') data.audit=await api('/audit-logs')
    else if(path==='/settings') [data.settings,data.notifications]=await Promise.all([api('/settings'),api('/notification-channels')])
  }catch(reason){showError(reason)}finally{loading.value=false}
}

function open(name, initial={}){Object.keys(form).forEach(key=>delete form[key]);Object.assign(form,initial);modal.value=name;clearMessages()}
function close(){modal.value='';sourceDetail.value=null;selectedSource.value='';targetGroups.value=[]}
async function submit(action, success){loading.value=true;clearMessages();try{await action();notice.value=success;close();await loadPage()}catch(reason){showError(reason)}finally{loading.value=false}}
async function createSource(){await submit(()=>api('/sources',{method:'POST',body:body({name:form.name,platform:form.platform,baseURL:form.baseURL,authMode:form.platform==='SUB2API'?(form.authMode||'PASSWORD'):'PASSWORD',username:form.username,password:form.password,accessToken:form.accessToken,refreshToken:form.refreshToken,valueNumerator:Number(form.valueNumerator),valueDenominator:Number(form.valueDenominator),scanIntervalSeconds:Number(form.interval||900)})}),'数据源已保存，首次扫描已开始')}
function editSource(row){open('source-edit',{id:row.id,name:row.name,baseURL:row.baseUrl,valueNumerator:1,valueDenominator:Number(row.valueDivisor||1),interval:row.scanIntervalSeconds||900})}
async function updateSource(){await submit(()=>api(`/sources/${form.id}`,{method:'PATCH',body:body({name:form.name,valueNumerator:Number(form.valueNumerator),valueDenominator:Number(form.valueDenominator),scanIntervalSeconds:Number(form.interval||900)})}),'数据源设置已更新，余额与倍率已按新比例重算')}
async function viewSource(id){
  selectedSource.value=id;loading.value=true;clearMessages();Object.keys(form).forEach(key=>delete form[key])
  try{
    const [detail,targets,settings]=await Promise.all([api(`/sources/${id}`),api('/targets'),api('/settings')])
    sourceDetail.value=detail;data.targets=targets;data.settings=settings
    Object.assign(form,{sourceGroupIDs:[],targetGroupIDs:[],targetID:writableTargets.value[0]?.id||'',priority:101,concurrency:1})
    if(form.targetID)await loadTargetGroups()
    modal.value='source-detail'
  }catch(reason){showError(reason)}finally{loading.value=false}
}
async function createTarget(){await submit(()=>api('/targets',{method:'POST',body:body({name:form.name,baseURL:form.baseURL,username:form.username,password:form.password,writeEnabled:!!form.writeEnabled})}),'目标节点已保存并开始同步')}
function editTarget(row){open('target-edit',{id:row.id,name:row.name,baseURL:row.baseUrl,username:'',password:'',writeEnabled:row.writeEnabled})}
async function updateTarget(){
  if((form.username&&!form.password)||(!form.username&&form.password)){showError(new Error('更新凭据时请同时填写管理员邮箱和密码'));return}
  await submit(()=>api(`/targets/${form.id}`,{method:'PATCH',body:body({name:form.name,username:form.username||'',password:form.password||'',writeEnabled:!!form.writeEnabled})}),'目标节点已更新并重新同步')
}
async function loadTargetGroups(){targetGroups.value=form.targetID?await api(`/targets/${form.targetID}/groups`):[];form.targetGroupIDs=[];form.sourceGroupIDs=(form.sourceGroupIDs||[]).filter(id=>!isGroupMapped(sourceDetail.value?.groups.find(group=>group.id===id)))}
function isGroupMapped(group){return !!group?.deployments?.some(item=>item.targetId===form.targetID)}
function mappedTargets(group){return (group.deployments||[]).map(item=>item.targetName).join('、')}
function toggleSourceGroups(){const available=(sourceDetail.value?.groups||[]).filter(group=>!isGroupMapped(group)).map(group=>group.id);form.sourceGroupIDs=form.sourceGroupIDs?.length===available.length?[]:available}
function toggleTargetGroups(){const available=targetGroups.value.map(group=>group.id);form.targetGroupIDs=form.targetGroupIDs?.length===available.length?[]:available}
async function deploySourceGroups(){
  if(!form.sourceGroupIDs?.length){showError(new Error('请至少选择一个源分组'));return}
  if(!form.targetID||!form.targetGroupIDs?.length){showError(new Error('请选择目标节点和目标分组'));return}
  await submit(()=>api(`/sources/${selectedSource.value}/deploy`,{method:'POST',body:body({targetID:form.targetID,sourceGroupIDs:form.sourceGroupIDs,targetGroupIDs:form.targetGroupIDs,priority:Number(form.priority||101),concurrency:Number(form.concurrency||1)})}),`已自动创建 ${form.sourceGroupIDs.length} 个专用 Key 和托管账号，默认停止调度`)
}
async function createPolicy(){await submit(()=>api('/policies',{method:'POST',body:body({name:form.name,scopeType:'GLOBAL',config:{maxMultiplier:Number(form.maxMultiplier||1),minSuccessRate:Number(form.minSuccessRate||95),minSamples:Number(form.minSamples||5),confirmationFailures:Number(form.confirmationFailures||3),cooldownMinutes:Number(form.cooldownMinutes||15)}})}),'策略草稿已创建')}
async function activatePolicy(policy){await action(()=>api(`/policies/${policy.id}/activate-version`,{method:'POST',body:body({version:policy.activeVersion||1})}),'策略已启用')}
async function action(run, success){loading.value=true;clearMessages();try{await run();notice.value=success;await loadPage()}catch(reason){showError(reason)}finally{loading.value=false}}
async function remove(path,label){if(!confirm(`确认删除“${label}”？`))return;await action(()=>api(path,{method:'DELETE'}),'已删除')}
async function channelAct(row,act){await action(()=>api(`/channels/${row.id}/${act}`,{method:'POST'}),act==='probe'?'探测任务已提交':'渠道状态已更新')}
async function decision(row,value){await action(()=>api(`/action-intents/${row.id}/${value}`,{method:'POST'}),value==='approve'?'动作已批准':'动作已拒绝')}
async function saveSettings(){const payload={};for(const key of ['shadow_mode','emergency_freeze','auto_approve'])payload[key]=!!data.settings[key];for(const key of ['probe_interval_seconds','scan_interval_seconds','max_daily_probe_cost_usd','min_healthy_channels','confirmation_failures','metric_window_minutes','min_error_samples','error_rate_threshold'])payload[key]=Number(data.settings[key]);await action(()=>api('/settings',{method:'PATCH',body:body(payload)}),'系统设置已保存')}
async function createNotification(){await submit(()=>api('/notification-channels',{method:'POST',body:body({name:form.name,apiKey:form.apiKey,fromEmail:form.fromEmail,toEmail:form.toEmail})}),'通知渠道已保存')}
async function testNotification(row){await action(()=>api(`/notification-channels/${row.id}/test`,{method:'POST'}),'测试邮件已发送')}
async function updateAccount(){
  clearMessages()
  if(form.newPassword && form.newPassword!==form.confirmPassword){showError(new Error('两次输入的新密码不一致'));return}
  loading.value=true
  try{
    operator.value=await api('/auth/account',{method:'PATCH',body:body({email:form.email,currentPassword:form.currentPassword,newPassword:form.newPassword||''})})
    close();notice.value='登录账号已更新，其他会话已退出'
  }catch(reason){showError(reason)}finally{loading.value=false}
}
async function runAutomation(){await action(()=>api('/automation/run',{method:'POST'}),'自动任务已提交')}
async function rescanSource(row){await action(()=>api(`/sources/${row.id}/scan`,{method:'POST'}),'扫描任务已提交')}
async function syncTarget(row){await action(()=>api(`/targets/${row.id}/test-connection`,{method:'POST'}),'同步任务已提交')}

function statusTone(value){if(['ACTIVE','ONLINE','HEALTHY','SUCCESS','EXECUTED','RESOLVED','SYNCED'].includes(value))return'success';if(['FAILED','OFFLINE','QUARANTINED','CREDENTIAL_BLOCKED','P0','P1'].includes(value))return'danger';if(['UNKNOWN','PENDING','VALIDATING','SUSPECT','ACKNOWLEDGED','DRAFT'].includes(value))return'warning';return'neutral'}
function statusText(value){return {UNKNOWN:'待同步',ACTIVE:'启用',ONLINE:'在线',OFFLINE:'离线',HEALTHY:'健康',SUSPECT:'待确认',QUARANTINED:'已隔离',MANUAL_HOLD:'人工暂停',DISCOVERED:'待探测',VALIDATING:'验证中',PENDING:'待审批',APPROVED:'已批准',REJECTED:'已拒绝',EXECUTED:'已执行',FAILED:'失败',OPEN:'待处理',ACKNOWLEDGED:'已确认',RESOLVED:'已恢复',SUCCESS:'成功',RUNNING:'运行中',IDLE:'待命',SYNCED:'已同步',DRAFT:'草稿'}[value]||value||'--'}
function date(value){return value?new Intl.DateTimeFormat('zh-CN',{month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit'}).format(new Date(value)):'--'}
function money(value){return value==null?'--':`$${Number(value).toFixed(2)}`}
function ratio(value){return value==null?'--':`${Number(value).toFixed(4)}x`}
function valueRatio(value){return `1 : ${Number(value||1).toLocaleString('zh-CN',{maximumFractionDigits:8,useGrouping:false})}`}
function minimumRatio(items){const values=items.map(item=>Number(item.multiplier)).filter(value=>Number.isFinite(value));return values.length?Math.min(...values):null}
</script>

<template>
  <div v-if="!token" class="login-page">
    <section class="login-panel">
      <div class="brand brand-login"><span class="brand-mark"><img src="/brand/channel-manager-logo.png" alt="" /></span><div><strong>渠道管家</strong><small>Channel Control Plane</small></div></div>
      <form class="login-form" @submit.prevent="login">
        <header><h1>管理员登录</h1></header>
        <label><span>邮箱</span><input name="email" type="email" autocomplete="username" required autofocus /></label>
        <label><span>密码</span><input name="password" type="password" autocomplete="current-password" required /></label>
        <div v-if="error" class="message error" role="alert">{{ error }}</div>
        <button class="btn primary full" :disabled="loading"><span v-if="loading" class="spinner" />登录</button>
      </form>
    </section>
    <aside class="login-scene" aria-hidden="true"><div class="scene-copy"><ShieldCheck :size="34"/><strong>生产安全控制面</strong><span>采集、判定与执行彼此隔离</span></div></aside>
  </div>

  <div v-else class="app-shell">
    <aside class="sidebar">
      <div class="brand"><span class="brand-mark"><img src="/brand/channel-manager-logo.png" alt="" /></span><div><strong>渠道管家</strong><small>{{ appVersion ? `v${appVersion}` : '版本读取中' }}</small></div></div>
      <nav>
        <section v-for="group in nav" :key="group.label"><span class="nav-group-label">{{ group.label }}</span><a v-for="([path,label,Icon]) in group.items" :key="path" :href="`#${path}`" :class="{active:route===path}" :aria-current="route===path?'page':undefined"><component :is="Icon" :size="18"/><span>{{ label }}</span><ChevronRight :size="14" /></a></section>
      </nav>
      <div class="sidebar-foot"><span class="sidebar-avatar">{{ (operator?.email||'管').slice(0,1).toUpperCase() }}</span><span class="sidebar-user-copy"><strong>{{ operator?.email||'管理员' }}</strong><small><i class="online-dot"/>管理员 · 在线</small></span><button class="icon-btn" title="退出登录" @click="logout()"><LogOut :size="17" /></button></div>
    </aside>
    <section class="workspace">
      <header class="topbar"><button class="icon-btn mobile-menu" title="打开导航" aria-controls="mobile-navigation" :aria-expanded="mobileOpen" @click="mobileOpen=true"><Menu :size="19" /></button><div class="topbar-title"><component :is="pageIcon" :size="18"/><strong>{{ pageTitle }}</strong></div><label v-if="showSearch" class="search"><Search :size="16"/><input v-model="search" :placeholder="`筛选${pageTitle}`" :aria-label="`筛选${pageTitle}`" /></label><div class="top-actions"><button class="icon-btn" title="刷新" :disabled="loading" @click="loadPage"><RefreshCw :class="{spinning:loading}" :size="18" /></button><button class="account-button" title="修改账号与密码" @click="open('account',{email:operator?.email||''})"><span class="account-avatar">{{ (operator?.email||'管').slice(0,1).toUpperCase() }}</span><span class="account-copy"><strong>{{ operator?.email||'账号设置' }}</strong><small>管理员</small></span><ChevronRight :size="14"/></button></div></header>
      <main>
        <div v-if="notice" class="message success" role="status" aria-live="polite"><Check :size="16"/>{{ notice }}</div><div v-if="error" class="message error" role="alert"><AlertTriangle :size="16"/>{{ error }}</div>
        <template v-if="route==='/overview'">
          <div class="page-head"><div><span class="eyebrow">TODAY</span><h1>运营总览</h1></div><button class="btn" @click="runAutomation"><Play :size="16"/>立即运行</button></div>
          <div v-if="loading" class="skeleton-grid"><i v-for="n in 6" :key="n" /></div>
          <template v-else><section class="metric-strip"><article><span>数据源</span><strong>{{ data.summary.sources||0 }}</strong><small>已启用平台</small></article><article><span>托管渠道</span><strong>{{ data.summary.channels||0 }}</strong><small>{{ data.summary.healthyChannels||0 }} 个健康</small></article><article><span>托管账号</span><strong>{{ data.summary.managedAccounts||0 }}</strong><small>目标节点账号</small></article><article><span>最低倍率</span><strong>{{ ratio(data.summary.minimumMultiplier) }}</strong><small>24 小时样本</small></article></section>
          <div class="overview-grid"><section class="panel safety-panel"><header><div><span class="eyebrow">SAFETY GATE</span><h2>生产安全</h2></div><ShieldCheck :size="22"/></header><div class="safety-state"><span :class="['safety-icon',data.summary.emergencyFreeze?'danger':'success']"><Pause v-if="data.summary.emergencyFreeze"/><Check v-else/></span><div><strong>{{ data.summary.emergencyFreeze?'紧急冻结':'写入闸门正常' }}</strong><small>{{ data.summary.shadowMode?'当前为影子模式':'允许执行已批准动作' }}</small></div></div><div class="mini-stats"><span><b>{{ data.summary.pendingActions||0 }}</b>待审批动作</span><span><b>{{ data.summary.openEvents||0 }}</b>活动事件</span></div></section>
          <section class="panel quick-panel"><header><div><span class="eyebrow">WORKFLOW</span><h2>工作流程</h2></div><Activity :size="22"/></header><ol><li><span>1</span><div><strong>市场采集</strong><small>数据源按周期同步</small></div></li><li><span>2</span><div><strong>渠道探测</strong><small>质量与模型能力验证</small></div></li><li><span>3</span><div><strong>策略判定</strong><small>生成可解释动作</small></div></li><li><span>4</span><div><strong>审批执行</strong><small>只写入托管账号</small></div></li></ol></section></div></template>
        </template>

        <template v-else-if="route==='/sources'">
          <div class="page-head"><div><h1>数据源</h1><span>{{ data.sources.length }} 个平台</span></div><button class="btn primary" @click="open('source',{platform:'SUB2API',authMode:'PASSWORD',valueNumerator:1,valueDenominator:1,interval:900})"><Plus :size="16"/>接入数据源</button></div>
          <div v-if="loading" class="table-loading"><span class="spinner"/>正在读取</div><StateBlock v-else-if="!data.sources.length" title="暂无数据源"><button class="btn primary" @click="open('source',{platform:'SUB2API',authMode:'PASSWORD',valueNumerator:1,valueDenominator:1,interval:900})"><Plus :size="16"/>接入数据源</button></StateBlock>
          <div v-else class="table-wrap"><table class="has-actions"><thead><tr><th>平台</th><th>类型</th><th>余额 / 倍率换算</th><th>连接</th><th>余额</th><th>分组</th><th>上次扫描</th><th><span class="sr-only">操作</span></th></tr></thead><tbody><tr v-for="row in filtered(data.sources)" :key="row.id"><td><button class="link" @click="viewSource(row.id)"><strong>{{ row.name }}</strong><small>{{ row.baseUrl }}</small></button></td><td>{{ row.platform }}</td><td class="ratio">{{ valueRatio(row.valueDivisor) }}</td><td><span :class="['badge',statusTone(row.scanStatus)]">{{ statusText(row.scanStatus) }}</span><small v-if="row.lastError" class="danger-text">{{ row.lastError }}</small></td><td>{{ money(row.balance) }}</td><td>{{ row.groupCount }}</td><td>{{ date(row.lastScanAt) }}</td><td><div class="row-actions"><button class="icon-btn" title="编辑数据源" @click="editSource(row)"><Pencil :size="16"/></button><button class="icon-btn" title="立即扫描" @click="rescanSource(row)"><RefreshCw :size="16"/></button><button class="icon-btn danger" title="删除" @click="remove(`/sources/${row.id}`,row.name)"><Trash2 :size="16"/></button></div></td></tr></tbody></table></div>
        </template>

        <template v-else-if="route==='/market'">
          <div class="page-head"><div><h1>市场大盘</h1><span>{{ data.market.length }} 个有效报价</span></div></div>
          <section class="market-ticker"><article><span>最低倍率</span><strong>{{ ratio(minimumRatio(data.market)) }}</strong></article><article><span>平均倍率</span><strong>{{ ratio(data.market.length?data.market.reduce((s,x)=>s+Number(x.multiplier||0),0)/data.market.length:null) }}</strong></article><article><span>数据源</span><strong>{{ new Set(data.market.map(x=>x.sourceName)).size }}</strong></article><article><span>30 日样本</span><strong>{{ data.history.length }}</strong></article></section>
          <div class="table-wrap"><table><thead><tr><th>排名</th><th>数据源</th><th>分组</th><th>口径</th><th>当前倍率</th><th>采集时间</th></tr></thead><tbody><tr v-for="(row,index) in filtered(data.market)" :key="row.id"><td class="rank">{{ String(index+1).padStart(2,'0') }}</td><td>{{ row.sourceName }}</td><td><strong>{{ row.name }}</strong></td><td>{{ row.groupType }}</td><td class="ratio">{{ ratio(row.multiplier) }}</td><td>{{ date(row.capturedAt) }}</td></tr></tbody></table></div>
        </template>

        <template v-else-if="route==='/targets'">
          <div class="page-head"><div><h1>目标节点</h1><span>{{ data.targets.length }} 个 Sub2API 节点</span></div><button class="btn primary" @click="open('target')"><Plus :size="16"/>接入节点</button></div>
          <StateBlock v-if="!loading&&!data.targets.length" title="暂无目标节点"/><div v-else class="tile-list"><article v-for="row in filtered(data.targets)" :key="row.id" class="target-tile"><header><span class="target-icon"><Network :size="20"/></span><div><strong>{{ row.name }}</strong><small>{{ row.baseUrl }}</small></div><span :class="['badge',statusTone(row.status)]">{{ statusText(row.status) }}</span></header><div v-if="row.lastError" class="target-error"><AlertTriangle :size="16"/><span><strong>同步失败</strong><small>{{ row.lastError }}</small></span></div><div class="tile-metrics"><span><b>{{ row.groupCount }}</b>分组</span><span><b>{{ row.managedCount }}</b>托管账号</span><span><b>{{ row.version||'--' }}</b>版本</span></div><footer><span><ShieldCheck :size="15"/>{{ row.writeEnabled?'允许托管写入':'只读' }}</span><div class="row-actions"><button class="icon-btn" title="编辑节点" @click="editTarget(row)"><Pencil :size="15"/></button><button class="btn small" @click="syncTarget(row)"><RefreshCw :size="14"/>同步</button><button class="icon-btn danger" title="删除" @click="remove(`/targets/${row.id}`,row.name)"><Trash2 :size="15"/></button></div></footer></article></div>
        </template>

        <template v-else-if="route==='/channels'">
          <div class="page-head"><div><h1>渠道雷达</h1><span>价格与探测质量</span></div></div>
          <div class="table-wrap"><table class="has-actions"><thead><tr><th>数据源 / Key</th><th>分组</th><th>倍率</th><th>主动探测</th><th>真实业务</th><th>首次响应 P95</th><th>状态</th><th>原因</th><th><span class="sr-only">操作</span></th></tr></thead><tbody><tr v-for="row in filtered(data.channels)" :key="row.id"><td><strong>{{ row.sourceName }}</strong><small>{{ row.keyName }}</small></td><td>{{ row.groupName }}</td><td class="ratio">{{ ratio(row.multiplier) }}</td><td>{{ row.successRate==null?'--':`${Number(row.successRate).toFixed(1)}%` }}<small>{{ row.probeSamples1h }} 个样本</small></td><td>{{ row.businessSuccessRate1h==null?'--':`${Number(row.businessSuccessRate1h).toFixed(1)}%` }}<small>{{ row.businessRequests1h }} 个请求</small></td><td>{{ row.firstTokenP95Ms==null?'--':`${(row.firstTokenP95Ms/1000).toFixed(2)} 秒` }}</td><td><span :class="['badge',statusTone(row.lifecycleState)]">{{ statusText(row.lifecycleState) }}</span></td><td>{{ row.stateReason||'--' }}</td><td><div class="row-actions"><button class="icon-btn" title="探测" @click="channelAct(row,'probe')"><Play :size="16"/></button><button class="icon-btn" :title="row.lifecycleState==='MANUAL_HOLD'?'恢复':'暂停'" @click="channelAct(row,row.lifecycleState==='MANUAL_HOLD'?'resume-validation':'manual-hold')"><component :is="row.lifecycleState==='MANUAL_HOLD'?RefreshCw:Pause" :size="16"/></button></div></td></tr></tbody></table></div>
        </template>

        <template v-else-if="route==='/managed'">
          <div class="page-head"><div><h1>托管账号</h1><span>{{ data.managed.length }} 个目标账号</span></div></div>
          <StateBlock v-if="!loading&&!data.managed.length" title="暂无托管账号"/><div v-else class="table-wrap"><table><thead><tr><th>账号</th><th>目标节点</th><th>来源</th><th>分组</th><th>优先级</th><th>并发</th><th>调度</th><th>同步</th></tr></thead><tbody><tr v-for="row in filtered(data.managed)" :key="row.id"><td><strong>{{ row.remoteName }}</strong><small>ID {{ row.remoteId }}</small></td><td>{{ row.targetName }}</td><td>{{ row.sourceName }}<small>{{ row.keyName }}</small></td><td><span v-for="group in row.targetGroups" :key="group.id" class="tag">{{ group.name }}</span></td><td>{{ row.priority }}</td><td>{{ row.concurrency }}</td><td><span :class="['badge',row.schedulable?'success':'neutral']">{{ row.schedulable?'运行':'停止' }}</span></td><td><span :class="['badge',statusTone(row.syncStatus)]">{{ statusText(row.syncStatus) }}</span></td></tr></tbody></table></div>
        </template>

        <template v-else-if="route==='/policies'">
          <div class="page-head"><div><h1>策略配置</h1><span>版本化准入与调度规则</span></div><button class="btn primary" @click="open('policy')"><Plus :size="16"/>新建策略</button></div>
          <div class="policy-list"><article v-for="row in filtered(data.policies)" :key="row.id" class="panel policy"><header><div><strong>{{ row.name }}</strong><small>{{ row.scopeType }} · v{{ row.activeVersion||1 }}</small></div><span :class="['badge',statusTone(row.status)]">{{ statusText(row.status) }}</span></header><dl><div><dt>倍率上限</dt><dd>{{ ratio(row.config.maxMultiplier) }}</dd></div><div><dt>最低成功率</dt><dd>{{ row.config.minSuccessRate||95 }}%</dd></div><div><dt>最少样本</dt><dd>{{ row.config.minSamples||5 }}</dd></div><div><dt>冷却</dt><dd>{{ row.config.cooldownMinutes||15 }} 分钟</dd></div></dl><footer><button v-if="row.status!=='ACTIVE'" class="btn primary small" @click="activatePolicy(row)"><Play :size="14"/>启用</button><button class="btn small" @click="action(()=>api(`/policies/${row.id}/simulate`,{method:'POST'}),'模拟完成，结果已生成')"><BarChart3 :size="14"/>模拟</button></footer></article></div>
        </template>

        <template v-else-if="route==='/scheduling'">
          <div class="page-head"><div><h1>调度运行</h1><span>{{ data.actions.filter(x=>x.status==='PENDING').length }} 个动作待审批</span></div><button class="btn" @click="runAutomation"><Play :size="16"/>运行评估</button></div>
          <div class="table-wrap"><table class="has-actions"><thead><tr><th>动作</th><th>原因</th><th>变更</th><th>状态</th><th>生成时间</th><th><span class="sr-only">操作</span></th></tr></thead><tbody><tr v-for="row in filtered(data.actions)" :key="row.id"><td><strong>{{ row.actionType }}</strong><small>{{ row.managedAccountId||'--' }}</small></td><td>{{ row.reason }}</td><td><code>{{ JSON.stringify(row.afterState) }}</code></td><td><span :class="['badge',statusTone(row.status)]">{{ statusText(row.status) }}</span><small v-if="row.error" class="danger-text">{{ row.error }}</small></td><td>{{ date(row.createdAt) }}</td><td><div v-if="row.status==='PENDING'" class="row-actions"><button class="btn primary small" @click="decision(row,'approve')"><Check :size="14"/>批准</button><button class="btn small" @click="decision(row,'reject')"><X :size="14"/>拒绝</button></div></td></tr></tbody></table></div>
        </template>

        <template v-else-if="route==='/events'">
          <div class="page-head"><div><h1>事件中心</h1><span>{{ data.events.filter(x=>x.status!=='RESOLVED').length }} 个活动事件 · 恢复后自动关闭</span></div></div>
          <div class="event-list"><article v-for="row in filtered(data.events)" :key="row.id" :class="['event',row.severity.toLowerCase()]" ><span class="severity">{{ row.severity }}</span><div><header><strong>{{ row.title }}</strong><span :class="['badge',statusTone(row.status)]">{{ statusText(row.status) }}</span></header><p>{{ row.detail }}</p><small>{{ row.category }} · {{ date(row.createdAt) }}</small></div></article></div>
        </template>

        <template v-else-if="route==='/audit'">
          <div class="page-head"><div><h1>审计日志</h1><span>追加写入，不可修改</span></div></div><div class="table-wrap"><table><thead><tr><th>时间</th><th>动作</th><th>对象</th><th>对象 ID</th><th>详情</th></tr></thead><tbody><tr v-for="row in filtered(data.audit)" :key="row.id"><td>{{ date(row.createdAt) }}</td><td><strong>{{ row.action }}</strong></td><td>{{ row.objectType }}</td><td><code>{{ row.objectId }}</code></td><td><code>{{ JSON.stringify(row.detail) }}</code></td></tr></tbody></table></div>
        </template>

        <template v-else-if="route==='/settings'">
          <div class="page-head"><div><h1>系统设置</h1><span>{{ data.settings.buildType }} · {{ data.settings.githubRepo }}</span></div><button class="btn primary" @click="saveSettings"><Check :size="16"/>保存设置</button></div>
          <div class="settings-layout"><section class="settings-section"><header><ShieldCheck :size="20"/><div><h2>安全闸门</h2></div></header><label class="toggle-row"><div><strong>影子模式</strong><small>保存后生成动作但不写入目标节点</small></div><input v-model="data.settings.shadow_mode" type="checkbox"/><span/></label><label class="toggle-row danger-row"><div><strong>紧急冻结</strong><small>保存后阻止全部远程写动作</small></div><input v-model="data.settings.emergency_freeze" type="checkbox"/><span/></label><label class="toggle-row"><div><strong>自动批准</strong><small>保存后生效，仅在关闭影子模式时执行</small></div><input v-model="data.settings.auto_approve" type="checkbox"/><span/></label></section>
          <section class="settings-section"><header><Activity :size="20"/><div><h2>采集与判定</h2></div></header><div class="form-grid"><label><span>探测周期（秒）</span><input v-model="data.settings.probe_interval_seconds" type="number" min="60"/></label><label><span>扫描周期（秒）</span><input v-model="data.settings.scan_interval_seconds" type="number" min="60"/></label><label><span>确认失败次数</span><input v-model="data.settings.confirmation_failures" type="number" min="1"/></label><label><span>指标窗口（分钟）</span><input v-model="data.settings.metric_window_minutes" type="number" min="1"/></label><label><span>最少异常样本</span><input v-model="data.settings.min_error_samples" type="number" min="1"/></label><label><span>异常率阈值（%）</span><input v-model="data.settings.error_rate_threshold" type="number" min="1" max="100"/></label></div></section>
          <section class="settings-section notification-settings"><header><UserCog :size="20"/><div><h2>邮件通知</h2></div><button class="btn primary small" @click="open('notification')"><Plus :size="14"/>添加</button></header><StateBlock v-if="!data.notifications.length" title="暂无通知渠道"/><div v-else class="notification-list"><div v-for="row in data.notifications" :key="row.id"><div><strong>{{ row.name }}</strong><small>{{ row.recipientHint }} · {{ row.lastTestAt?date(row.lastTestAt):'未测试' }}</small></div><span :class="['badge',statusTone(row.status)]">{{ statusText(row.status) }}</span><button class="btn small" @click="testNotification(row)">测试</button></div></div></section></div>
        </template>
      </main>
    </section>
    <button v-if="mobileOpen" class="mobile-backdrop" title="关闭导航" aria-label="关闭导航" @click="mobileOpen=false"/><aside v-if="mobileOpen" id="mobile-navigation" class="mobile-drawer" role="dialog" aria-modal="true" aria-label="主导航"><header class="brand"><span class="brand-mark"><img src="/brand/channel-manager-logo.png" alt="" /></span><strong>渠道管家</strong><button class="icon-btn" title="关闭" @click="mobileOpen=false"><X :size="18"/></button></header><nav><section v-for="group in nav" :key="group.label"><span class="nav-group-label">{{ group.label }}</span><a v-for="([path,label,Icon]) in group.items" :key="path" :href="`#${path}`" :class="{active:route===path}" :aria-current="route===path?'page':undefined"><component :is="Icon" :size="18"/>{{ label }}</a></section></nav></aside>
  </div>

  <ModalShell v-if="modal==='source'" title="接入数据源" @close="close"><form class="modal-form" @submit.prevent="createSource"><label><span>平台名称</span><input v-model="form.name" required/></label><label><span>平台类型</span><select v-model="form.platform" @change="form.authMode='PASSWORD'"><option value="SUB2API">Sub2API</option><option value="NEW_API">New API</option></select></label><label class="full"><span>平台地址</span><input v-model="form.baseURL" type="url" placeholder="https://" required/></label><fieldset v-if="form.platform==='SUB2API'" class="auth-mode full"><legend>认证方式</legend><label :class="{active:form.authMode==='PASSWORD'}"><input v-model="form.authMode" type="radio" value="PASSWORD"/><span>账号密码</span></label><label :class="{active:form.authMode==='TOKEN'}"><input v-model="form.authMode" type="radio" value="TOKEN"/><span>Access Token + RT</span></label></fieldset><template v-if="form.platform!=='SUB2API'||form.authMode!=='TOKEN'"><label><span>{{ form.platform==='SUB2API'?'管理员邮箱':'用户名' }}</span><input v-model="form.username" :type="form.platform==='SUB2API'?'email':'text'" required/></label><label><span>密码</span><input v-model="form.password" type="password" required/></label></template><template v-else><label><span>Access Token</span><input v-model="form.accessToken" type="password" autocomplete="off" required/></label><label><span>Refresh Token (RT)</span><input v-model="form.refreshToken" type="password" autocomplete="off" required/></label></template><label><span>余额 / 倍率换算</span><span class="ratio-input"><input v-model="form.valueNumerator" type="number" min="0.00000001" step="any" required/><b>:</b><input v-model="form.valueDenominator" type="number" min="0.00000001" step="any" required/></span></label><label><span>扫描周期（秒）</span><input v-model="form.interval" type="number" min="60"/></label><footer class="full"><button type="button" class="btn" @click="close">取消</button><button class="btn primary" :disabled="loading">保存</button></footer></form></ModalShell>
  <ModalShell v-if="modal==='source-edit'" title="编辑数据源" @close="close"><form class="modal-form" @submit.prevent="updateSource"><label class="full"><span>平台名称</span><input v-model="form.name" required/></label><label class="full"><span>平台地址</span><input v-model="form.baseURL" disabled/></label><label><span>余额 / 倍率换算</span><span class="ratio-input"><input v-model="form.valueNumerator" type="number" min="0.00000001" step="any" required/><b>:</b><input v-model="form.valueDenominator" type="number" min="0.00000001" step="any" required/></span></label><label><span>扫描周期（秒）</span><input v-model="form.interval" type="number" min="60"/></label><footer class="full"><button type="button" class="btn" @click="close">取消</button><button class="btn primary" :disabled="loading">保存并重算</button></footer></form></ModalShell>
  <ModalShell v-if="modal==='source-detail'&&sourceDetail" :title="sourceDetail.source.name" wide @close="close">
    <form class="mapping-workspace" @submit.prevent="deploySourceGroups">
      <div class="mapping-context">
        <div><Database :size="18"/><span><small>数据源</small><strong>{{ sourceDetail.source.name }}</strong></span></div>
        <ArrowRight :size="18"/>
        <div><Network :size="18"/><span><small>目标节点</small><strong>{{ selectedTarget?.name||'尚未选择' }}</strong></span></div>
        <span class="mapping-cardinality">1 : N</span>
      </div>
      <div class="mapping-builder">
        <section class="mapping-step">
          <header><span class="step-index">1</span><div><h3>选择源分组</h3><small>每个源分组创建一个独立托管账号</small></div><button type="button" class="btn small" @click="toggleSourceGroups"><Check :size="14"/>全选可用</button></header>
          <div class="source-option-list">
            <label v-for="group in sourceDetail.groups" :key="group.id" class="source-option" :class="{selected:form.sourceGroupIDs?.includes(group.id),mapped:isGroupMapped(group)}">
              <input v-model="form.sourceGroupIDs" type="checkbox" :value="group.id" :disabled="isGroupMapped(group)" :aria-label="`选择 ${group.name}`"/>
              <span class="source-option-copy"><strong>{{ group.name }}</strong><small>{{ group.description||`远端 ID ${group.remoteId}` }}</small></span>
              <span class="source-option-meta"><b>{{ ratio(group.multiplier) }}</b><small v-if="isGroupMapped(group)">已映射到 {{ selectedTarget?.name }}</small><small v-else-if="group.deployments?.length">另有 {{ mappedTargets(group) }}</small></span>
            </label>
          </div>
        </section>
        <section class="mapping-step">
          <header><span class="step-index">2</span><div><h3>选择目标分组</h3><small>一个托管账号可同时加入多个分组</small></div></header>
          <label class="target-node-select"><span>目标节点</span><select v-model="form.targetID" required @change="loadTargetGroups"><option value="" disabled>请选择</option><option v-for="item in writableTargets" :key="item.id" :value="item.id">{{ item.name }}</option></select></label>
          <div class="target-group-head"><span>目标分组 <b>{{ form.targetGroupIDs?.length||0 }}/{{ targetGroups.length }}</b></span><button v-if="targetGroups.length" type="button" class="btn small" @click="toggleTargetGroups"><Check :size="14"/>全选</button></div>
          <div class="target-option-list">
            <div v-if="!form.targetID" class="empty-inline">请先选择目标节点</div><div v-else-if="!targetGroups.length" class="empty-inline">该节点尚未同步分组</div>
            <label v-for="group in targetGroups" :key="group.id" class="target-option" :class="{selected:form.targetGroupIDs?.includes(group.id)}"><input v-model="form.targetGroupIDs" type="checkbox" :value="group.id"/><span><strong>{{ group.name }}</strong><small>ID {{ group.remoteId }}</small></span></label>
          </div>
        </section>
      </div>
      <section class="mapping-preview">
        <header><span class="step-index">3</span><div><h3>映射预览</h3><small>每一行都是一个源分组到多个目标分组的一对多关系</small></div></header>
        <div v-if="!selectedSourceGroups.length||!selectedTargetGroups.length" class="mapping-preview-empty">选择两侧分组后，这里会显示最终映射关系</div>
        <div v-else class="mapping-preview-list">
          <div v-for="group in selectedSourceGroups" :key="group.id" class="mapping-preview-row"><span class="preview-source"><strong>{{ group.name }}</strong><small>源分组</small></span><ArrowRight :size="18"/><span class="preview-targets"><span v-for="targetGroup in selectedTargetGroups" :key="targetGroup.id">{{ targetGroup.name }}</span></span></div>
        </div>
      </section>
      <footer class="mapping-submit">
        <div class="mapping-options"><label><span>优先级</span><input v-model="form.priority" type="number" min="101"/></label><label><span>并发</span><input v-model="form.concurrency" type="number" min="1"/></label></div>
        <div class="mapping-submit-action"><div v-if="data.settings.shadow_mode" class="message warning"><AlertTriangle :size="16"/>当前为影子模式，关闭后才能创建</div><small v-else>将创建 {{ form.sourceGroupIDs?.length||0 }} 个托管账号，每个绑定 {{ form.targetGroupIDs?.length||0 }} 个目标分组</small><button class="btn primary" :disabled="loading||data.settings.shadow_mode||!form.sourceGroupIDs?.length||!form.targetGroupIDs?.length"><Workflow :size="16"/>确认创建</button></div>
      </footer>
    </form>
  </ModalShell>
  <ModalShell v-if="modal==='target'" title="接入目标节点" @close="close"><form class="modal-form" @submit.prevent="createTarget"><label><span>节点名称</span><input v-model="form.name" required/></label><label class="full"><span>节点地址</span><input v-model="form.baseURL" type="url" placeholder="https://" required/></label><label><span>管理员邮箱</span><input v-model="form.username" type="email" required/></label><label><span>管理员密码</span><input v-model="form.password" type="password" required/></label><label class="check-row full"><input v-model="form.writeEnabled" type="checkbox"/><span><strong>允许创建和维护托管账号</strong><small>既有账号始终只读</small></span></label><footer class="full"><button type="button" class="btn" @click="close">取消</button><button class="btn primary">保存</button></footer></form></ModalShell>
  <ModalShell v-if="modal==='target-edit'" title="编辑目标节点" @close="close"><form class="modal-form" @submit.prevent="updateTarget"><label class="full"><span>节点名称</span><input v-model="form.name" required/></label><label class="full"><span>节点地址</span><input v-model="form.baseURL" disabled/></label><label><span>管理员邮箱（不修改可留空）</span><input v-model="form.username" type="email" autocomplete="username"/></label><label><span>管理员密码（不修改可留空）</span><input v-model="form.password" type="password" autocomplete="new-password"/></label><label class="check-row full"><input v-model="form.writeEnabled" type="checkbox"/><span><strong>允许创建和维护托管账号</strong><small>既有账号始终只读</small></span></label><div v-if="error" class="message error full" role="alert"><AlertTriangle :size="16"/>{{ error }}</div><footer class="full"><button type="button" class="btn" @click="close">取消</button><button class="btn primary" :disabled="loading">保存并同步</button></footer></form></ModalShell>
  <ModalShell v-if="modal==='policy'" title="新建策略" @close="close"><form class="modal-form" @submit.prevent="createPolicy"><label class="full"><span>策略名称</span><input v-model="form.name" required/></label><label><span>倍率上限</span><input v-model="form.maxMultiplier" type="number" min="0.0001" step="0.0001" value="1"/></label><label><span>最低成功率（%）</span><input v-model="form.minSuccessRate" type="number" min="0" max="100" value="95"/></label><label><span>最少样本</span><input v-model="form.minSamples" type="number" min="1" value="5"/></label><label><span>确认失败次数</span><input v-model="form.confirmationFailures" type="number" min="1" value="3"/></label><label><span>冷却时间（分钟）</span><input v-model="form.cooldownMinutes" type="number" min="1" value="15"/></label><footer class="full"><button type="button" class="btn" @click="close">取消</button><button class="btn primary">创建</button></footer></form></ModalShell>
  <ModalShell v-if="modal==='notification'" title="添加邮件通知" @close="close"><form class="modal-form" @submit.prevent="createNotification"><label><span>渠道名称</span><input v-model="form.name" required/></label><label><span>Resend API Key</span><input v-model="form.apiKey" type="password" required/></label><label><span>发件邮箱</span><input v-model="form.fromEmail" type="email" required/></label><label><span>收件邮箱</span><input v-model="form.toEmail" type="email" required/></label><footer class="full"><button type="button" class="btn" @click="close">取消</button><button class="btn primary">保存</button></footer></form></ModalShell>
  <ModalShell v-if="modal==='account'" title="账号与密码" @close="close"><form class="modal-form" @submit.prevent="updateAccount"><label class="full"><span>登录邮箱</span><input v-model.trim="form.email" type="email" autocomplete="username" required/></label><label class="full"><span>当前密码</span><input v-model="form.currentPassword" type="password" autocomplete="current-password" required/></label><label><span>新密码（不修改可留空）</span><input v-model="form.newPassword" type="password" autocomplete="new-password" minlength="10" maxlength="72"/></label><label><span>确认新密码</span><input v-model="form.confirmPassword" type="password" autocomplete="new-password" :required="!!form.newPassword"/></label><div v-if="error" class="message error full" role="alert"><AlertTriangle :size="16"/>{{ error }}</div><footer class="full"><button type="button" class="btn" @click="close">取消</button><button class="btn primary" :disabled="loading"><span v-if="loading" class="spinner"/>保存账号</button></footer></form></ModalShell>
</template>
