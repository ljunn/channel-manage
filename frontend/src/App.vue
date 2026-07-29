<script setup>
import { computed, onMounted, reactive, ref, watch } from 'vue'
import {
  Activity, AlertTriangle, ArrowRight, BarChart3, BellRing, Bot, Check, ChevronDown, ChevronRight, CircleDollarSign, ClipboardList,
  Database, Download, Eye, EyeOff, FileClock, Gauge, History, KeyRound, LogOut, Menu, Network, Pause, Pencil, Play, Plus,
  RefreshCw, Search, Settings, ShieldCheck, SlidersHorizontal, Trash2, UserCog, Workflow, X,
} from '@lucide/vue'
import ModalShell from './components/ModalShell.vue'
import MarketTrendChart from './components/MarketTrendChart.vue'
import PaginationBar from './components/PaginationBar.vue'
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
const page = ref(1)
const pageSize = ref(15)
const appVersion = ref('')
const data = reactive({ summary: {}, sources: [], targets: [], channels: [], managed: [], market: {groups:[],trend:[],channels:[]}, policies: [], scheduling: [], actions: [], events: [], audit: [], settings: {}, notifications: [] })
const sourceDetail = ref(null)
const selectedSource = ref('')
const targetGroups = ref([])
const sourceOpening = ref(false)
const targetGroupsLoading = ref(false)
const deploymentBusy = ref(false)
const deploymentJobs = ref([])
const policyTargetGroups = ref([])
const form = reactive({})
const marketMetric = ref('average')
const marketGroup = ref('all')
const marketTab = ref('low')
const sourceBindingFilter = ref('all')
const sourceStatusFilter = ref('all')
const sourceSort = ref('created')
const schedulingTab = ref('status')
const schedulingGroup = ref('all')
const expandedSchedulingGroups = ref(new Set())
const hiddenSchedulingGroups = ref(readHiddenSchedulingGroups())
const showHiddenSchedulingGroups = ref(false)
const simulationResult = ref(null)
const systemVersion = reactive({currentVersion:'',buildType:'',repository:'',updateSupported:false,restartSupported:false,rollbackAvailable:false,restartPending:false,pendingVersion:''})
const updateInfo = reactive({latestVersion:'',hasUpdate:false,name:'',body:'',htmlUrl:'',publishedAt:''})
const updateBusy = ref(false)
const updateReady = ref(false)
let targetGroupsRequest = 0
let deploymentPollTimer = 0

const nav = [
  { label: '经营视图', items: [['/overview','运营总览',Gauge],['/market','市场大盘',CircleDollarSign],['/sources','数据源',Database]] },
  { label: '生产调度', items: [['/scheduling','调度运行',Workflow],['/channels','渠道雷达',Activity],['/managed','托管账号',Bot],['/targets','目标节点',Network],['/policies','策略配置',SlidersHorizontal]] },
  { label: '审计与系统', items: [['/events','事件中心',AlertTriangle],['/audit','审计日志',FileClock],['/settings','系统设置',Settings]] },
]
const routeNames = Object.fromEntries(nav.flatMap(group => group.items.map(([path,label]) => [path,label])))
const pageTitle = computed(() => routeNames[route.value] || '渠道管家')
const pageIcon = computed(() => nav.flatMap(group => group.items).find(([path]) => path === route.value)?.[2] || Gauge)
const searchableRoutes = new Set(['/sources','/scheduling','/channels','/managed','/targets','/policies','/events','/audit'])
const showSearch = computed(() => searchableRoutes.has(route.value))
const writableTargets = computed(() => data.targets.filter(item => item.writeEnabled))
const configuredPolicyScopes = computed(() => new Set(data.policies.map(item=>item.scopeId).filter(Boolean)))
const selectedSourceGroups = computed(() => (sourceDetail.value?.groups||[]).filter(group => form.sourceGroupIDs?.includes(group.id)))
const selectedTargetGroups = computed(() => targetGroups.value.filter(group => form.targetGroupIDs?.includes(group.id)))
const mappingPairs = computed(() => selectedSourceGroups.value.flatMap(sourceGroup => selectedTargetGroups.value.map(targetGroup => ({ id:`${sourceGroup.id}:${targetGroup.id}`, sourceGroup, targetGroup }))))
const selectedTarget = computed(() => writableTargets.value.find(item => item.id===form.targetID))
const activeDeploymentJob = computed(() => deploymentJobs.value.find(item=>item.status==='QUEUED'||item.status==='RUNNING')||null)
const latestDeploymentJob = computed(() => deploymentJobs.value[0]||null)
const filtered = items => !search.value ? items : items.filter(item => JSON.stringify(item).toLowerCase().includes(search.value.toLowerCase()))
const paged = items => filtered(items).slice((page.value-1)*pageSize.value,page.value*pageSize.value)
const filteredCount = items => filtered(items).length
const eventCategoryLabel = value => ({SOURCE_BALANCE:'账户余额',SOURCE_SCAN:'数据源扫描',TARGET_SYNC:'目标节点同步',GROUP_AVAILABILITY:'分组可用性',ACTION_EXECUTION:'远程调度写入',ACCOUNT_PLATFORM_SYNC:'账号平台校正',CHANNEL_PROBE:'渠道探测'})[value]||value
const ranking = index => (page.value-1)*pageSize.value+index+1
const sourceRows = computed(() => {
  let items=filtered(data.sources)
  if(sourceBindingFilter.value==='unbound')items=items.filter(item=>Number(item.managedAccountCount||0)===0)
  else if(sourceBindingFilter.value==='partial')items=items.filter(item=>Number(item.boundGroupCount||0)>0&&Number(item.boundGroupCount||0)<Number(item.groupCount||0))
  else if(sourceBindingFilter.value==='complete')items=items.filter(item=>Number(item.groupCount||0)>0&&Number(item.boundGroupCount||0)>=Number(item.groupCount||0))
  if(sourceStatusFilter.value!=='all')items=items.filter(item=>item.scanStatus===sourceStatusFilter.value)
  const result=[...items]
  const nullLast=(left,right,direction=1)=>left==null&&right==null?0:left==null?1:right==null?-1:direction*(Number(left)-Number(right))
  if(sourceSort.value==='accountsAsc')result.sort((a,b)=>Number(a.managedAccountCount||0)-Number(b.managedAccountCount||0))
  else if(sourceSort.value==='accountsDesc')result.sort((a,b)=>Number(b.managedAccountCount||0)-Number(a.managedAccountCount||0))
  else if(sourceSort.value==='balanceDesc')result.sort((a,b)=>nullLast(a.balance,b.balance,-1))
  else if(sourceSort.value==='balanceAsc')result.sort((a,b)=>nullLast(a.balance,b.balance,1))
  else if(sourceSort.value==='groupsDesc')result.sort((a,b)=>Number(b.groupCount||0)-Number(a.groupCount||0))
  else result.sort((a,b)=>new Date(b.createdAt)-new Date(a.createdAt))
  return result
})
const sourcePagedRows = computed(() => sourceRows.value.slice((page.value-1)*pageSize.value,page.value*pageSize.value))
function groupSchedulingItems(items){
  const groups=new Map()
  for(const item of items){
    if(!groups.has(item.targetGroupId))groups.set(item.targetGroupId,{id:item.targetGroupId,name:item.targetGroup,targetName:item.targetName,policyName:item.policyName,running:[],stopped:[]})
    groups.get(item.targetGroupId)[item.schedulable?'running':'stopped'].push(item)
  }
  return [...groups.values()].map(group=>{
    group.running.sort((left,right)=>Number(left.priority)-Number(right.priority)||left.remoteName.localeCompare(right.remoteName,'zh-CN'))
    group.stopped.sort((left,right)=>Number(right.fastValidation)-Number(left.fastValidation)||left.remoteName.localeCompare(right.remoteName,'zh-CN'))
    group.recovering=group.stopped.filter(item=>item.fastValidation).length
    return group
  }).sort((left,right)=>left.targetName.localeCompare(right.targetName,'zh-CN')||left.name.localeCompare(right.name,'zh-CN'))
}
const schedulingGroups = computed(() => [...new Map(data.scheduling.map(item=>[item.targetGroupId,{id:item.targetGroupId,name:item.targetGroup}])).values()].sort((a,b)=>a.name.localeCompare(b.name,'zh-CN')))
const visibleSchedulingGroups = computed(() => schedulingGroups.value.filter(group=>!hiddenSchedulingGroups.value.has(group.id)))
const allSchedulingSections = computed(() => groupSchedulingItems(data.scheduling))
const visibleSchedulingSections = computed(() => allSchedulingSections.value.filter(group=>!hiddenSchedulingGroups.value.has(group.id)))
const hiddenSchedulingSections = computed(() => allSchedulingSections.value.filter(group=>hiddenSchedulingGroups.value.has(group.id)))
const schedulingSections = computed(() => groupSchedulingItems(filtered(data.scheduling).filter(item=>!hiddenSchedulingGroups.value.has(item.targetGroupId)&&(schedulingGroup.value==='all'||item.targetGroupId===schedulingGroup.value))))
const schedulingPagedSections = computed(() => schedulingSections.value.slice((page.value-1)*pageSize.value,page.value*pageSize.value))
const schedulingRunningCount = computed(() => data.scheduling.filter(item=>item.schedulable).length)
const schedulingRecoveringCount = computed(() => data.scheduling.filter(item=>!item.schedulable&&item.fastValidation).length)
const marketGroupChannels = computed(() => data.market.channels.filter(item=>marketGroup.value==='all'||item.targetGroupId===marketGroup.value))
const marketRankedChannels = computed(() => marketGroupChannels.value.filter(item=>marketTab.value!=='stable'||(item.lifecycleState==='HEALTHY'&&Number(item.probeSamples7d||0)+Number(item.businessSamples7d||0)>0)).sort((a,b)=>marketTab.value==='stable'?(Number(b.qualityScore)-Number(a.qualityScore)||Number(b.probeSamples7d+b.businessSamples7d)-Number(a.probeSamples7d+a.businessSamples7d)):(Number(a.qualityScore)-Number(b.qualityScore))))
const marketPagedChannels = computed(() => marketRankedChannels.value.slice((page.value-1)*pageSize.value,page.value*pageSize.value))
const marketUniqueChannels = computed(() => new Set(marketGroupChannels.value.map(item=>item.id)).size)
const marketLatestValue = computed(() => {
  const points=data.market.trend.filter(item=>marketGroup.value==='all'||item.targetGroupId===marketGroup.value).filter(item=>item[marketMetric.value]!=null)
  if(!points.length)return null
  const latest=Math.max(...points.map(item=>new Date(item.capturedAt).getTime()))
  const values=points.filter(item=>new Date(item.capturedAt).getTime()===latest).map(item=>Number(item[marketMetric.value]))
  return values.reduce((sum,value)=>sum+value,0)/values.length
})

window.addEventListener('hashchange', () => { route.value = location.hash.slice(1) || '/overview'; mobileOpen.value = false })
watch(route, () => { search.value=''; page.value=1; clearMessages(); if(token.value) void loadPage() })
watch(search, () => { page.value=1 })
watch(pageSize, () => { page.value=1 })
watch([marketGroup,marketTab], () => { page.value=1 })
watch([sourceBindingFilter,sourceStatusFilter,sourceSort], () => { page.value=1 })
watch([schedulingTab,schedulingGroup], () => { page.value=1 })
onMounted(async () => { void loadVersion(); if (token.value) { try { operator.value=await api('/auth/me'); await loadPage() } catch {} } else route.value='/login' })

async function loadVersion(){
  try{const response=await fetch('/health',{headers:{accept:'application/json'}});if(response.ok)appVersion.value=(await response.json()).version||''}catch{}
}

async function api(path, init={}) {
	const timeout=init.timeout||30000
	const requestInit={...init}
	delete requestInit.timeout
  const headers = new Headers(init.headers || {})
  headers.set('accept','application/json')
  if (init.body) headers.set('content-type','application/json')
  if (token.value) headers.set('authorization',`Bearer ${token.value}`)
  let response
  try { response = await fetch(`/api${path}`, { ...requestInit, headers, signal: AbortSignal.timeout(timeout) }) }
  catch (reason) { throw new Error(reason?.name === 'TimeoutError' ? '请求超时' : '无法连接服务') }
  const payload = await response.json().catch(() => ({}))
  if (!response.ok) { if(response.status===401 && path!='/auth/login') logout(false); const fallback=response.status===502&&path.endsWith('/deploy')?'绑定请求被网关中断，请稍后刷新列表确认结果；未完成批次会自动回滚':`请求失败 (${response.status})`; throw new Error(payload.error?.message || fallback) }
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
    else if(path==='/market') data.market=await api('/market/dashboard')
    else if(path==='/policies') [data.policies,data.targets]=await Promise.all([api('/policies'),api('/targets')])
    else if(path==='/scheduling') [data.scheduling,data.actions]=await Promise.all([api('/scheduling/status'),api('/action-intents')])
    else if(path==='/events') data.events=await api('/events')
    else if(path==='/audit') data.audit=await api('/audit-logs')
    else if(path==='/settings') { const [settings,notifications,version]=await Promise.all([api('/settings'),api('/notification-channels'),api('/system/version')]);data.settings=settings;data.notifications=notifications;Object.assign(systemVersion,version);updateReady.value=!!version.restartPending }
  }catch(reason){showError(reason)}finally{loading.value=false}
}

function open(name, initial={}){Object.keys(form).forEach(key=>delete form[key]);Object.assign(form,initial);modal.value=name;clearMessages()}
function close(){targetGroupsRequest++;targetGroupsLoading.value=false;clearTimeout(deploymentPollTimer);deploymentPollTimer=0;deploymentJobs.value=[];modal.value='';sourceDetail.value=null;selectedSource.value='';targetGroups.value=[]}
async function submit(action, success){if(loading.value)return;loading.value=true;clearMessages();try{await action();notice.value=success;close();await loadPage()}catch(reason){showError(reason)}finally{loading.value=false}}
async function createSource(){await submit(()=>api('/sources',{method:'POST',body:body({name:form.name,platform:form.platform,baseURL:form.baseURL,authMode:form.platform==='SUB2API'?(form.authMode||'PASSWORD'):'PASSWORD',username:form.username,password:form.password,accessToken:form.accessToken,refreshToken:form.refreshToken,valueNumerator:Number(form.valueNumerator),valueDenominator:Number(form.valueDenominator),scanIntervalSeconds:Number(form.interval||900)})}),'数据源已保存，首次扫描已开始')}
function editSource(row){open('source-edit',{id:row.id,name:row.name,platform:row.platform,baseURL:row.baseUrl,valueNumerator:1,valueDenominator:Number(row.valueDivisor||1),interval:row.scanIntervalSeconds||900,reauth:false,authMode:'PASSWORD',username:'',password:'',accessToken:'',refreshToken:''})}
async function updateSource(){
  const credentials=form.reauth?{authMode:form.authMode,username:form.username,password:form.password,accessToken:form.accessToken,refreshToken:form.refreshToken}:{}
  await submit(()=>api(`/sources/${form.id}`,{method:'PATCH',body:body({name:form.name,valueNumerator:Number(form.valueNumerator),valueDenominator:Number(form.valueDenominator),scanIntervalSeconds:Number(form.interval||900),...credentials})}),form.reauth?'数据源认证已更新，正在重新扫描':'数据源设置已更新，余额与倍率已按新比例重算')
}
async function viewSource(id){
	if(sourceOpening.value)return
	selectedSource.value=id;sourceOpening.value=true;targetGroups.value=[];clearMessages();Object.keys(form).forEach(key=>delete form[key])
	try{
		const [detail,targets,settings,jobs]=await Promise.all([api(`/sources/${id}`),api('/targets'),api('/settings'),api(`/sources/${id}/deployments`)])
		sourceDetail.value=detail;data.targets=targets;data.settings=settings
		deploymentJobs.value=jobs
		Object.assign(form,{sourceGroupIDs:[],targetGroupIDs:[],targetID:writableTargets.value[0]?.id||'',priority:1000,concurrency:1000})
		modal.value='source-detail'
		if(form.targetID)void loadTargetGroups()
		if(activeDeploymentJob.value)scheduleDeploymentPoll(id)
	}catch(reason){showError(reason)}finally{sourceOpening.value=false}
}
async function createTarget(){await submit(()=>api('/targets',{method:'POST',body:body({name:form.name,baseURL:form.baseURL,username:form.username,password:form.password,writeEnabled:!!form.writeEnabled})}),'目标节点已保存并开始同步')}
function editTarget(row){open('target-edit',{id:row.id,name:row.name,baseURL:row.baseUrl,username:'',password:'',writeEnabled:row.writeEnabled})}
async function updateTarget(){
  if((form.username&&!form.password)||(!form.username&&form.password)){showError(new Error('更新凭据时请同时填写管理员邮箱和密码'));return}
  await submit(()=>api(`/targets/${form.id}`,{method:'PATCH',body:body({name:form.name,username:form.username||'',password:form.password||'',writeEnabled:!!form.writeEnabled})}),'目标节点已更新并重新同步')
}
async function loadTargetGroups(){
	const targetID=form.targetID
	const request=++targetGroupsRequest
	targetGroups.value=[];form.targetGroupIDs=[];form.sourceGroupIDs=(form.sourceGroupIDs||[]).filter(id=>!isGroupMapped(sourceDetail.value?.groups.find(group=>group.id===id)))
	if(!targetID){targetGroupsLoading.value=false;return}
	targetGroupsLoading.value=true
	try{
		const groups=await api(`/targets/${targetID}/groups`)
		if(request===targetGroupsRequest&&form.targetID===targetID)targetGroups.value=groups
	}catch(reason){if(request===targetGroupsRequest)showError(reason)}finally{if(request===targetGroupsRequest)targetGroupsLoading.value=false}
}
function isGroupMapped(group){return !!group?.deployments?.some(item=>item.targetId===form.targetID)}
function mappedTargets(group){return (group.deployments||[]).map(item=>item.targetName).join('、')}
function toggleSourceGroups(){const available=(sourceDetail.value?.groups||[]).filter(group=>!isGroupMapped(group)).map(group=>group.id);form.sourceGroupIDs=form.sourceGroupIDs?.length===available.length?[]:available}
function toggleTargetGroups(){const available=targetGroups.value.map(group=>group.id);form.targetGroupIDs=form.targetGroupIDs?.length===available.length?[]:available}
async function deploySourceGroups(){
	if(deploymentBusy.value||activeDeploymentJob.value)return
  if(!form.sourceGroupIDs?.length){showError(new Error('请至少选择一个源分组'));return}
  if(!form.targetID||!form.targetGroupIDs?.length){showError(new Error('请选择目标节点和目标分组'));return}
	const sourceID=selectedSource.value
	const sourceGroupCount=form.sourceGroupIDs.length
  const accountCount=form.sourceGroupIDs.length*form.targetGroupIDs.length
	deploymentBusy.value=true;clearMessages()
	try{
		const job=await api(`/sources/${sourceID}/deploy`,{method:'POST',body:body({targetID:form.targetID,sourceGroupIDs:form.sourceGroupIDs,targetGroupIDs:form.targetGroupIDs,priority:Number(form.priority||1000),concurrency:Number(form.concurrency||1000)})})
		deploymentJobs.value=[{id:job.jobId,status:job.status,progressDone:job.progressDone,progressTotal:job.progressTotal,error:'',result:{}},...deploymentJobs.value]
		form.sourceGroupIDs=[];form.targetGroupIDs=[]
		notice.value=`后台任务已提交：将创建 ${sourceGroupCount} 个专用 Key 和 ${accountCount} 个独立托管账号`
		scheduleDeploymentPoll(sourceID)
	}catch(reason){showError(reason)}finally{deploymentBusy.value=false}
}
function scheduleDeploymentPoll(sourceID){
	clearTimeout(deploymentPollTimer)
	deploymentPollTimer=setTimeout(()=>void pollDeploymentJobs(sourceID),1500)
}
async function pollDeploymentJobs(sourceID){
	if(selectedSource.value!==sourceID||modal.value!=='source-detail')return
	try{
		deploymentJobs.value=await api(`/sources/${sourceID}/deployments`)
		if(activeDeploymentJob.value){scheduleDeploymentPoll(sourceID);return}
		const latest=latestDeploymentJob.value
		if(latest?.status==='COMPLETED'){
			const [detail,sources]=await Promise.all([api(`/sources/${sourceID}`),api('/sources')])
			sourceDetail.value=detail;data.sources=sources
			notice.value=`后台创建完成：${latest.result?.sourceKeysCreated||0} 个专用 Key，${latest.result?.created||0} 个独立托管账号`
		}else if(latest?.status==='FAILED')showError(new Error(latest.error||'后台创建失败'))
	}catch(reason){showError(reason);scheduleDeploymentPoll(sourceID)}
}
async function openPolicy(){open('policy',{targetID:writableTargets.value[0]?.id||'',targetGroupID:'',mode:'PRICE',allowEqualMultiplier:false,minSuccessRate:95,minSamples:5});await loadPolicyTargetGroups()}
async function loadPolicyTargetGroups(){policyTargetGroups.value=form.targetID?await api(`/targets/${form.targetID}/groups`):[];form.targetGroupID=''}
async function createPolicy(){await submit(()=>api('/policies',{method:'POST',body:body({name:form.name,scopeType:'TARGET_GROUP',scopeID:form.targetGroupID,config:policyConfigPayload()})}),'分组策略草稿已创建')}
function editPolicy(row){open('policy-edit',{id:row.id,name:row.name,targetName:row.targetName,targetGroupName:row.targetGroupName,mode:row.config.mode||'PRICE',allowEqualMultiplier:row.config.allowEqualMultiplier===true,minSuccessRate:row.config.minSuccessRate??95,minSamples:row.config.minSamples??5})}
function policyConfigPayload(){return {mode:form.mode,allowEqualMultiplier:form.allowEqualMultiplier===true,minSuccessRate:Number(form.minSuccessRate??95),minSamples:Number(form.minSamples??5)}}
async function updatePolicy(){await submit(()=>api(`/policies/${form.id}`,{method:'PATCH',body:body({name:form.name,config:policyConfigPayload()})}),'策略已更新并生成新版本')}
async function activatePolicy(policy){await action(()=>api(`/policies/${policy.id}/activate-version`,{method:'POST',body:body({version:policy.activeVersion||1})}),'策略已启用')}
async function deactivatePolicy(policy){if(!confirm(`确认停用“${policy.name}”的自动调度？托管账号会保留当前启停状态和优先级，不会自动重置。`))return;await action(()=>api(`/policies/${policy.id}/deactivate`,{method:'POST'}),'自动调度已停用')}
async function removePolicy(policy){if(!confirm(`确认删除策略“${policy.name}”？历史版本会一并删除，托管账号和渠道不会被删除。`))return;await action(()=>api(`/policies/${policy.id}`,{method:'DELETE'}),'策略已删除')}
async function simulatePolicy(policy){if(loading.value)return;loading.value=true;clearMessages();try{simulationResult.value={policy,result:await api(`/policies/${policy.id}/simulate`,{method:'POST'})};modal.value='policy-simulation'}catch(reason){showError(reason)}finally{loading.value=false}}
async function action(run, success){loading.value=true;clearMessages();try{await run();notice.value=success;await loadPage()}catch(reason){showError(reason)}finally{loading.value=false}}
async function remove(path,label){if(!confirm(`确认删除“${label}”？`))return;await action(()=>api(path,{method:'DELETE'}),'已删除')}
async function channelAct(row,act){await action(()=>api(`/channels/${row.id}/${act}`,{method:'POST'}),act==='probe'?'探测任务已提交':'渠道状态已更新')}
async function saveSettings(){const payload={probe_models:Object.fromEntries((data.settings.probe_groups||[]).map(group=>[group.id,group.probeModel]))};for(const key of ['shadow_mode','emergency_freeze','email_alert_source_balance','email_alert_source_scan','email_alert_target_sync','email_alert_group_availability','email_alert_action_execution','email_alert_platform_sync','email_alert_recovery'])payload[key]=!!data.settings[key];for(const key of ['probe_interval_seconds','scan_interval_seconds','max_daily_probe_cost_usd','min_healthy_channels','confirmation_failures','metric_window_minutes','min_error_samples','error_rate_threshold','balance_alert_work_hours','balance_alert_night_hours','balance_alert_weekend_hours'])payload[key]=Number(data.settings[key]);await action(()=>api('/settings',{method:'PATCH',body:body(payload)}),'系统设置已保存')}
async function createNotification(){await submit(()=>api('/notification-channels',{method:'POST',body:body({name:form.name,apiKey:form.apiKey,fromEmail:form.fromEmail,toEmail:form.toEmail})}),'通知渠道已保存')}
async function testNotification(row){await action(()=>api(`/notification-channels/${row.id}/test`,{method:'POST'}),'测试邮件已发送')}
async function checkUpdate(){updateBusy.value=true;clearMessages();try{Object.assign(updateInfo,await api('/system/check-updates?force=true',{timeout:60000}));notice.value=updateInfo.hasUpdate?`发现新版本 v${updateInfo.latestVersion}`:'当前已是最新版本'}catch(reason){showError(reason)}finally{updateBusy.value=false}}
async function installUpdate(){updateBusy.value=true;clearMessages();try{const result=await api('/system/update',{method:'POST',body:'{}',timeout:900000});if(result.alreadyUpToDate){notice.value='当前已是最新版本';return}updateReady.value=true;notice.value=`v${result.version} 已安装，重启后生效`;Object.assign(systemVersion,await api('/system/version'))}catch(reason){showError(reason)}finally{updateBusy.value=false}}
async function rollbackUpdate(){if(!confirm('确认回滚到上次在线更新前的版本并重启服务？'))return;updateBusy.value=true;clearMessages();try{await api('/system/rollback',{method:'POST',body:'{}'});await restartUpdatedService()}catch(reason){showError(reason);updateBusy.value=false}}
async function restartUpdatedService(){updateBusy.value=true;clearMessages();try{await api('/system/restart',{method:'POST',body:'{}'});notice.value='服务正在重启';await waitForRestart()}catch(reason){showError(reason);updateBusy.value=false}}
async function waitForRestart(){for(let attempt=0;attempt<60;attempt++){await new Promise(resolve=>setTimeout(resolve,2000));try{const response=await fetch('/health',{cache:'no-store'});if(response.ok){location.reload();return}}catch{}}error.value='服务重启时间过长，请稍后刷新页面';updateBusy.value=false}
async function updateAccount(){
  clearMessages()
  if(form.newPassword && form.newPassword!==form.confirmPassword){showError(new Error('两次输入的新密码不一致'));return}
  loading.value=true
  try{
    operator.value=await api('/auth/account',{method:'PATCH',body:body({email:form.email,currentPassword:form.currentPassword,newPassword:form.newPassword||''})})
    close();notice.value='登录账号已更新，其他会话已退出'
  }catch(reason){showError(reason)}finally{loading.value=false}
}
function editManagedPriority(row){open('managed-priority',{id:row.id,name:row.remoteName,priority:row.priority})}
async function updateManagedPriority(){await submit(()=>api(`/managed-accounts/${form.id}/priority`,{method:'PATCH',body:body({priority:Number(form.priority)})}),'优先级已同步到目标节点')}
function editManagedConcurrency(row){open('managed-concurrency',{id:row.id,name:row.remoteName,concurrency:row.concurrency})}
async function updateManagedConcurrency(){await submit(()=>api(`/managed-accounts/${form.id}/concurrency`,{method:'PATCH',body:body({concurrency:Number(form.concurrency)})}),'并发已同步到目标节点')}
async function runAutomation(){
  if(loading.value)return
  loading.value=true;clearMessages()
  try{
    await api('/automation/run',{method:'POST'})
    notice.value='自动评估已提交，后台正在处理'
    await new Promise(resolve=>setTimeout(resolve,2000))
    await loadPage()
    notice.value='自动评估已提交，当前状态已刷新；执行中的同步会继续更新'
  }catch(error){failure.value=error.message}
  finally{loading.value=false}
}
async function rescanSource(row){await action(()=>api(`/sources/${row.id}/scan`,{method:'POST'}),'扫描任务已提交')}
async function syncTarget(row){await action(()=>api(`/targets/${row.id}/test-connection`,{method:'POST'}),'同步任务已提交')}

function statusTone(value){if(['ACTIVE','ONLINE','HEALTHY','SUCCESS','EXECUTED','RESOLVED','SYNCED','COMPLETED'].includes(value))return'success';if(['FAILED','OFFLINE','QUARANTINED','CREDENTIAL_BLOCKED','AUTH_REQUIRED','P0','P1'].includes(value))return'danger';if(['UNKNOWN','PENDING','QUEUED','RUNNING','VALIDATING','SUSPECT','ACKNOWLEDGED','DRAFT'].includes(value))return'warning';return'neutral'}
function statusText(value){return {UNKNOWN:'待同步',ACTIVE:'启用',ONLINE:'在线',OFFLINE:'离线',HEALTHY:'健康',SUSPECT:'待确认',QUARANTINED:'已隔离',MANUAL_HOLD:'人工暂停',DISCOVERED:'待探测',VALIDATING:'验证中',PENDING:'待审批',QUEUED:'排队中',APPROVED:'已批准',REJECTED:'已拒绝',EXECUTED:'已执行',FAILED:'失败',AUTH_REQUIRED:'需要重新认证',OPEN:'待处理',ACKNOWLEDGED:'已确认',RESOLVED:'已恢复',SUCCESS:'成功',COMPLETED:'已完成',RUNNING:'运行中',IDLE:'待命',SYNCED:'已同步',DRAFT:'草稿'}[value]||value||'--'}
function date(value){return value?new Intl.DateTimeFormat('zh-CN',{month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit'}).format(new Date(value)):'--'}
function money(value){return value==null?'--':`$${Number(value).toFixed(2)}`}
function balanceEta(row){if(row.balanceEtaHours==null)return'正在积累消耗样本';const hours=Number(row.balanceEtaHours);if(hours<1)return`预计可用 ${Math.max(1,Math.round(hours*60))} 分钟`;if(hours<48)return`预计可用 ${hours.toFixed(1)} 小时`;return`预计可用 ${(hours/24).toFixed(1)} 天`}
function ratio(value){return value==null?'--':`${Number(value).toFixed(4)}x`}
function multiplierLabel(value){return value==null?'倍率未提供':`倍率 ×${Number(value).toFixed(4)}`}
function valueRatio(value){return `1 : ${Number(value||1).toLocaleString('zh-CN',{maximumFractionDigits:8,useGrouping:false})}`}
function coveragePercent(bound,total){return total?`${Math.round(Number(bound||0)*100/Number(total))}%`:'--'}
function sourceBindingText(row){if(!Number(row.managedAccountCount||0))return'未绑定';if(Number(row.boundGroupCount||0)>=Number(row.groupCount||0))return'已全部绑定';return'部分绑定'}
function readHiddenSchedulingGroups(){
  try{return new Set(JSON.parse(localStorage.getItem('channel_manage_hidden_scheduling_groups')||'[]'))}catch{return new Set()}
}
function persistHiddenSchedulingGroups(next){
  hiddenSchedulingGroups.value=next
  try{localStorage.setItem('channel_manage_hidden_scheduling_groups',JSON.stringify([...next]))}catch{}
}
function hideSchedulingGroup(id){
  const next=new Set(hiddenSchedulingGroups.value)
  next.add(id)
  persistHiddenSchedulingGroups(next)
  if(schedulingGroup.value===id)schedulingGroup.value='all'
  const expanded=new Set(expandedSchedulingGroups.value)
  expanded.delete(id)
  expandedSchedulingGroups.value=expanded
  page.value=1
}
function restoreSchedulingGroup(id){
  const next=new Set(hiddenSchedulingGroups.value)
  next.delete(id)
  persistHiddenSchedulingGroups(next)
  if(!hiddenSchedulingSections.value.length)showHiddenSchedulingGroups.value=false
  page.value=1
}
function restoreAllSchedulingGroups(){persistHiddenSchedulingGroups(new Set());showHiddenSchedulingGroups.value=false;page.value=1}
function toggleSchedulingGroup(id){const next=new Set(expandedSchedulingGroups.value);next.has(id)?next.delete(id):next.add(id);expandedSchedulingGroups.value=next}
function schedulingOutageText(group){if(!group.policyName)return'未配置启用策略';if(group.recovering)return`暂无可用账号，${group.recovering} 个正在快速恢复`;return'暂无可用账号，候选均被策略阻断'}
function validationEta(row){if(!row.fastValidation)return'';const seconds=Number(row.estimatedValidationSeconds||0);if(seconds<=0)return'下一轮评估';if(seconds<60)return`约 ${seconds} 秒`;return`约 ${Math.ceil(seconds/60)} 分钟`}
function schedulingReason(row){
  const reasons=row.reasons?.length?row.reasons.join('；'):''
  const wait=row.fastValidation&&row.estimatedValidationSeconds>0?`；快速验证预计还需 ${validationEta(row)}`:''
  if(row.schedulable&&row.eligible)return'符合策略，正在参与调度'
  if(row.schedulable&&!row.eligible)return`当前仍在参与，下一次同步将停止：${reasons||'不符合策略'}${wait}`
  if(!row.schedulable&&row.eligible)return'符合策略，等待同步恢复'
  if(reasons)return reasons+wait
  return'未参与调度'
}
function actionTitle(row){if(row.actionType==='SET_SCHEDULABLE')return row.afterState?.schedulable?'恢复参与调度':'停止参与调度';if(row.actionType==='SET_PRIORITY')return'调整调度优先级';return row.actionType}
function actionChange(row){if(row.actionType==='SET_SCHEDULABLE')return `${row.beforeState?.schedulable?'参与':'停止'} → ${row.afterState?.schedulable?'参与':'停止'}`;if(row.actionType==='SET_PRIORITY')return `${row.beforeState?.priority??'--'} → ${row.afterState?.priority??'--'}`;return JSON.stringify(row.afterState)}
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
		  <template v-else><section class="metric-strip"><article><span>数据源</span><strong>{{ data.summary.sources||0 }}</strong><small>{{ data.summary.unboundSources||0 }} 个尚未绑定</small></article><article><span>源分组覆盖率</span><strong>{{ coveragePercent(data.summary.boundSourceGroups,data.summary.totalSourceGroups) }}</strong><small>{{ data.summary.boundSourceGroups||0 }} / {{ data.summary.totalSourceGroups||0 }} 个已创建账号</small></article><article><span>托管账号</span><strong>{{ data.summary.managedAccounts||0 }}</strong><small>{{ data.summary.healthyChannels||0 }} 个渠道健康</small></article><article><span>待关注数据源</span><strong>{{ data.summary.attentionSources?.length||0 }}</strong><small>{{ data.summary.openEvents||0 }} 个活动事件</small></article></section>
		  <div class="overview-ops-grid"><section class="panel overview-list"><header><div><span class="eyebrow">ACTION QUEUE</span><h2>需要处理的数据源</h2></div><button class="link" @click="go('/sources')">查看全部 <ArrowRight :size="14"/></button></header><StateBlock v-if="!data.summary.attentionSources?.length" title="当前没有待关注数据源"/><div v-else class="overview-source-list"><button v-for="row in data.summary.attentionSources" :key="row.id" class="overview-source-row" @click="go('/sources')"><span><strong>{{ row.name }}</strong><small>{{ sourceBindingText(row) }} · {{ row.boundGroupCount||0 }}/{{ row.groupCount||0 }} 个分组 · {{ row.managedAccountCount||0 }} 个账号</small></span><span class="overview-source-side"><b>{{ money(row.balance) }}</b><small :class="{'danger-text':row.scanStatus==='FAILED'}">{{ row.scanStatus==='FAILED'?'扫描失败':statusText(row.scanStatus) }}</small></span></button></div></section><section class="panel overview-list"><header><div><span class="eyebrow">BALANCE WATCH</span><h2>余额分布</h2></div><CircleDollarSign :size="21"/></header><div class="balance-columns"><div><h3>余额较低</h3><span v-for="row in (data.summary.lowestBalanceSources||[])" :key="`low-${row.id}`"><strong>{{ row.name }}</strong><b>{{ money(row.balance) }}</b></span><small v-if="!data.summary.lowestBalanceSources?.length">暂无余额数据</small></div><div><h3>余额较高</h3><span v-for="row in (data.summary.highestBalanceSources||[])" :key="`high-${row.id}`"><strong>{{ row.name }}</strong><b>{{ money(row.balance) }}</b></span><small v-if="!data.summary.highestBalanceSources?.length">暂无余额数据</small></div></div></section></div>
          <div class="overview-grid"><section class="panel safety-panel"><header><div><span class="eyebrow">SAFETY GATE</span><h2>生产安全</h2></div><ShieldCheck :size="22"/></header><div class="safety-state"><span :class="['safety-icon',data.summary.emergencyFreeze?'danger':'success']"><Pause v-if="data.summary.emergencyFreeze"/><Check v-else/></span><div><strong>{{ data.summary.emergencyFreeze?'紧急冻结':'写入闸门正常' }}</strong><small>{{ data.summary.shadowMode?'当前为影子模式':'允许执行已批准动作' }}</small></div></div><div class="mini-stats"><span><b>{{ data.summary.pendingActions||0 }}</b>待审批动作</span><span><b>{{ data.summary.openEvents||0 }}</b>活动事件</span></div></section>
		  <section class="panel quick-panel"><header><div><span class="eyebrow">QUALITY SIGNAL</span><h2>渠道健康</h2></div><Activity :size="22"/></header><div class="safety-state"><span class="safety-icon success"><Check/></span><div><strong>{{ data.summary.healthyChannels||0 }} / {{ data.summary.channels||0 }} 个渠道健康</strong><small>仅统计本系统已托管的目标渠道</small></div></div><div class="mini-stats"><span><b>{{ ratio(data.summary.minimumMultiplier) }}</b>当前最低倍率</span><span><b>{{ data.summary.unboundSourceGroups||0 }}</b>未绑定源分组</span></div></section></div></template>
        </template>

        <template v-else-if="route==='/sources'">
          <div class="page-head"><div><h1>数据源</h1><span>{{ data.sources.length }} 个平台</span></div><button class="btn primary" @click="open('source',{platform:'SUB2API',authMode:'PASSWORD',valueNumerator:1,valueDenominator:1,interval:900})"><Plus :size="16"/>接入数据源</button></div>
          <div v-if="loading" class="table-loading"><span class="spinner"/>正在读取</div><StateBlock v-else-if="!data.sources.length" title="暂无数据源"><button class="btn primary" @click="open('source',{platform:'SUB2API',authMode:'PASSWORD',valueNumerator:1,valueDenominator:1,interval:900})"><Plus :size="16"/>接入数据源</button></StateBlock>
          <template v-else><div class="source-controls"><label><span>绑定状态</span><select v-model="sourceBindingFilter"><option value="all">全部</option><option value="unbound">未绑定账号</option><option value="partial">部分绑定</option><option value="complete">已全部绑定</option></select></label><label><span>扫描状态</span><select v-model="sourceStatusFilter"><option value="all">全部状态</option><option value="SUCCESS">扫描成功</option><option value="AUTH_REQUIRED">需要重新认证</option><option value="FAILED">扫描失败</option><option value="RUNNING">扫描中</option></select></label><label><span>排序</span><select v-model="sourceSort"><option value="created">最近接入</option><option value="accountsAsc">托管账号少 → 多</option><option value="accountsDesc">托管账号多 → 少</option><option value="balanceDesc">余额高 → 低</option><option value="balanceAsc">余额低 → 高</option><option value="groupsDesc">源分组多 → 少</option></select></label><span class="source-result-count">{{ sourceRows.length }} 个符合条件</span></div><StateBlock v-if="!sourceRows.length" title="没有符合条件的数据源"/><div v-else class="table-wrap"><table class="has-actions"><thead><tr><th>平台</th><th>类型</th><th>余额 / 倍率换算</th><th>连接</th><th>余额预测</th><th>绑定覆盖</th><th>上次扫描</th><th><span class="sr-only">操作</span></th></tr></thead><tbody><tr v-for="row in sourcePagedRows" :key="row.id"><td><button class="link" @click="viewSource(row.id)"><strong>{{ row.name }}</strong><small>{{ row.baseUrl }}</small></button></td><td>{{ row.platform }}</td><td class="ratio">{{ valueRatio(row.valueDivisor) }}</td><td><span :class="['badge',statusTone(row.scanStatus)]">{{ statusText(row.scanStatus) }}</span><small v-if="row.lastError" class="danger-text">{{ row.lastError }}</small></td><td class="balance-forecast"><strong>{{ money(row.balance) }}</strong><small>{{ balanceEta(row) }}</small><small v-if="row.balanceBurnRate!=null">消耗 {{ money(row.balanceBurnRate) }} / 小时</small></td><td class="binding-progress"><strong>{{ row.boundGroupCount||0 }} / {{ row.groupCount||0 }} 个源分组</strong><small>{{ row.managedAccountCount||0 }} 个托管账号 · {{ sourceBindingText(row) }}</small></td><td>{{ date(row.lastScanAt) }}</td><td><div class="row-actions"><button class="icon-btn" title="编辑数据源" @click="editSource(row)"><Pencil :size="16"/></button><button class="icon-btn" title="立即扫描" @click="rescanSource(row)"><RefreshCw :size="16"/></button><button class="icon-btn danger" title="删除" @click="remove(`/sources/${row.id}`,row.name)"><Trash2 :size="16"/></button></div></td></tr></tbody></table></div></template>
          <PaginationBar v-if="!loading&&sourceRows.length" v-model:page="page" v-model:page-size="pageSize" :total="sourceRows.length"/>
        </template>

        <template v-else-if="route==='/market'">
          <div class="page-head market-head"><div><h1>渠道倍率趋势</h1><span>仅统计已绑定并由本系统托管的渠道</span></div><label class="market-group-select"><span>查看范围</span><select v-model="marketGroup"><option value="all">全部分组总览</option><option v-for="group in data.market.groups" :key="group.id" :value="group.id">{{ group.targetName }} / {{ group.name }}</option></select></label></div>
          <section class="market-ticker"><article><span>已对接分组</span><strong>{{ data.market.groups.length }}</strong></article><article><span>当前渠道</span><strong>{{ marketUniqueChannels }}</strong></article><article><span>当前{{ {average:'平均',median:'中位',minimum:'最低'}[marketMetric] }}倍率</span><strong>{{ ratio(marketLatestValue) }}</strong></article><article><span>趋势样本</span><strong>{{ data.market.trend.length }}</strong></article></section>
          <section class="market-trend-panel">
            <header><div><h2>30 天倍率变化</h2><small>每小时取每个源分组最后一次采样，再按目标分组聚合</small></div><div class="segmented" aria-label="统计口径"><button :class="{active:marketMetric==='average'}" @click="marketMetric='average'">平均值</button><button :class="{active:marketMetric==='median'}" @click="marketMetric='median'">中位数</button><button :class="{active:marketMetric==='minimum'}" @click="marketMetric='minimum'">最低值</button></div></header>
            <StateBlock v-if="!loading&&!data.market.trend.length" title="暂无托管渠道倍率历史"/><MarketTrendChart v-else :groups="data.market.groups" :points="data.market.trend" :metric="marketMetric" :selected-group="marketGroup"/>
          </section>
          <section class="market-channel-panel">
            <header class="market-tabs"><div role="tablist" aria-label="渠道榜单"><button role="tab" :aria-selected="marketTab==='low'" :class="{active:marketTab==='low'}" @click="marketTab='low'">低分渠道</button><button role="tab" :aria-selected="marketTab==='stable'" :class="{active:marketTab==='stable'}" @click="marketTab='stable'">稳定渠道</button></div><span>{{ marketGroup==='all'?'全部分组总览':data.market.groups.find(group=>group.id===marketGroup)?.name }}</span></header>
            <StateBlock v-if="!loading&&!marketRankedChannels.length" title="该范围暂无托管渠道"/>
            <div v-else class="market-channel-list"><article v-for="(row,index) in marketPagedChannels" :key="`${row.targetGroupId}:${row.id}`"><span class="channel-rank">{{ String(ranking(index)).padStart(2,'0') }}</span><div class="channel-identity"><strong>{{ row.sourceName }}</strong><small>{{ row.sourceGroupName }}</small></div><div><span>倍率</span><strong>{{ ratio(row.multiplier) }}</strong></div><div><span>质量分</span><strong>{{ Number(row.qualityScore).toFixed(1) }}</strong></div><div><span>7 天探测</span><strong>{{ row.probeSuccessRate7d==null?'--':`${Number(row.probeSuccessRate7d).toFixed(1)}%` }}</strong><small>{{ row.probeSamples7d }} 个样本</small></div><div><span>7 天业务</span><strong>{{ row.businessSuccessRate7d==null?'--':`${Number(row.businessSuccessRate7d).toFixed(1)}%` }}</strong><small>{{ row.businessSamples7d }} 个请求</small></div><span :class="['badge',statusTone(row.lifecycleState)]">{{ statusText(row.lifecycleState) }}</span></article></div>
            <PaginationBar v-if="!loading" v-model:page="page" v-model:page-size="pageSize" :total="marketRankedChannels.length"/>
          </section>
        </template>

        <template v-else-if="route==='/targets'">
          <div class="page-head"><div><h1>目标节点</h1><span>{{ data.targets.length }} 个 Sub2API 节点</span></div><button class="btn primary" @click="open('target')"><Plus :size="16"/>接入节点</button></div>
          <StateBlock v-if="!loading&&!data.targets.length" title="暂无目标节点"/><div v-else class="tile-list"><article v-for="row in paged(data.targets)" :key="row.id" class="target-tile"><header><span class="target-icon"><Network :size="20"/></span><div><strong>{{ row.name }}</strong><small>{{ row.baseUrl }}</small></div><span :class="['badge',statusTone(row.status)]">{{ statusText(row.status) }}</span></header><div v-if="row.lastError" class="target-error"><AlertTriangle :size="16"/><span><strong>同步失败</strong><small>{{ row.lastError }}</small></span></div><div class="tile-metrics"><span><b>{{ row.groupCount }}</b>分组</span><span><b>{{ row.managedCount }}</b>托管账号</span><span><b>{{ row.version||'--' }}</b>版本</span></div><footer><span><ShieldCheck :size="15"/>{{ row.writeEnabled?'允许托管写入':'只读' }}</span><div class="row-actions"><button class="icon-btn" title="编辑节点" @click="editTarget(row)"><Pencil :size="15"/></button><button class="btn small" @click="syncTarget(row)"><RefreshCw :size="14"/>同步</button><button class="icon-btn danger" title="删除" @click="remove(`/targets/${row.id}`,row.name)"><Trash2 :size="15"/></button></div></footer></article></div>
          <PaginationBar v-if="!loading" v-model:page="page" v-model:page-size="pageSize" :total="filteredCount(data.targets)"/>
        </template>

        <template v-else-if="route==='/channels'">
          <div class="page-head"><div><h1>渠道雷达</h1><span>价格与探测质量</span></div></div>
          <div class="table-wrap"><table class="has-actions"><thead><tr><th>数据源 / Key</th><th>分组</th><th>倍率</th><th>主动探测</th><th>真实业务</th><th>首次响应 P95</th><th>状态</th><th>原因</th><th><span class="sr-only">操作</span></th></tr></thead><tbody><tr v-for="row in paged(data.channels)" :key="row.id"><td><strong>{{ row.sourceName }}</strong><small>{{ row.keyName }}</small></td><td>{{ row.groupName }}</td><td class="ratio">{{ ratio(row.multiplier) }}</td><td>{{ row.successRate==null?'--':`${Number(row.successRate).toFixed(1)}%` }}<small>{{ row.probeSamples1h }} 个样本</small></td><td>{{ row.businessSuccessRate1h==null?'--':`${Number(row.businessSuccessRate1h).toFixed(1)}%` }}<small>{{ row.businessRequests1h }} 个请求</small></td><td>{{ row.firstTokenP95Ms==null?'--':`${(row.firstTokenP95Ms/1000).toFixed(2)} 秒` }}</td><td><span :class="['badge',statusTone(row.lifecycleState)]">{{ statusText(row.lifecycleState) }}</span></td><td>{{ row.stateReason||'--' }}</td><td><div class="row-actions"><button class="icon-btn" title="探测" @click="channelAct(row,'probe')"><Play :size="16"/></button><button class="icon-btn" :title="row.lifecycleState==='MANUAL_HOLD'?'恢复':'暂停'" @click="channelAct(row,row.lifecycleState==='MANUAL_HOLD'?'resume-validation':'manual-hold')"><component :is="row.lifecycleState==='MANUAL_HOLD'?RefreshCw:Pause" :size="16"/></button></div></td></tr></tbody></table></div>
          <PaginationBar v-model:page="page" v-model:page-size="pageSize" :total="filteredCount(data.channels)"/>
        </template>

        <template v-else-if="route==='/managed'">
          <div class="page-head"><div><h1>托管账号</h1><span>{{ data.managed.length }} 个目标账号</span></div></div>
          <StateBlock v-if="!loading&&!data.managed.length" title="暂无托管账号"/><div v-else class="table-wrap"><table><thead><tr><th>账号</th><th>账号类型</th><th>目标节点</th><th>来源</th><th>分组</th><th>优先级</th><th>并发</th><th>调度</th><th>同步</th></tr></thead><tbody><tr v-for="row in paged(data.managed)" :key="row.id"><td><strong>{{ row.remoteName }}</strong><small>ID {{ row.remoteId }}</small></td><td><span class="badge info">{{ row.platform }}</span></td><td>{{ row.targetName }}</td><td>{{ row.sourceName }}<small>{{ row.keyName }}</small></td><td><span v-for="group in row.targetGroups" :key="group.id" class="tag">{{ group.name }} · {{ group.platform }}</span></td><td><button class="link inline-edit" title="修改并同步优先级" @click="editManagedPriority(row)">{{ row.priority }} <Pencil :size="13"/></button></td><td><button class="link inline-edit" title="修改并同步并发" @click="editManagedConcurrency(row)">{{ row.concurrency }} <Pencil :size="13"/></button></td><td><span :class="['badge',row.schedulable?'success':'neutral']">{{ row.schedulable?'运行':'停止' }}</span></td><td><span :class="['badge',statusTone(row.syncStatus)]">{{ statusText(row.syncStatus) }}</span><small v-if="row.lastError" class="danger-text">{{ row.lastError }}</small></td></tr></tbody></table></div>
          <PaginationBar v-if="!loading" v-model:page="page" v-model:page-size="pageSize" :total="filteredCount(data.managed)"/>
        </template>

        <template v-else-if="route==='/policies'">
          <div class="page-head"><div><h1>策略配置</h1><span>每 15 秒评估恢复候选并同步调度状态与优先级</span></div><button class="btn primary" @click="openPolicy"><Plus :size="16"/>新建分组策略</button></div>
          <div class="policy-list"><article v-for="row in paged(data.policies)" :key="row.id" class="panel policy"><header><div><strong>{{ row.name }}</strong><small>{{ row.targetName }} / {{ row.targetGroupName }} · v{{ row.activeVersion||1 }}</small></div><span :class="['badge',statusTone(row.status)]">{{ row.status==='ACTIVE'?'自动调度中':'未启用调度' }}</span></header><div :class="['policy-scheduling',row.status==='ACTIVE'?'active':'inactive']"><Workflow :size="17"/><div><strong>{{ row.status==='ACTIVE'?`${row.schedulableCount} / ${row.managedCount} 个账号参与调度`:'自动调度未运行' }}</strong><small>{{ row.status==='ACTIVE'?`每 ${row.evaluationIntervalSeconds} 秒重新评估，并直接同步到目标节点`:'启用后才会自动调整账号状态和优先级' }}</small></div></div><dl><div><dt>排序方式</dt><dd>{{ row.config.mode==='SPEED'?'首 Token P95 从快到慢':'源倍率从低到高' }}</dd></div><div><dt>写入优先级</dt><dd>1000 起连续排列</dd></div><div><dt>参与条件</dt><dd>健康 · {{ row.config.allowEqualMultiplier?'倍率不高于目标':'倍率严格低于目标' }}</dd></div><div><dt>{{ row.metricWindowDays||7 }} 天样本门槛</dt><dd>≥ {{ row.config.minSamples||5 }} 次 · 成功率 ≥ {{ row.config.minSuccessRate||95 }}%</dd></div></dl><p class="policy-effect">不满足条件的账号自动退出调度；恢复满足条件后自动重新加入。</p><footer><button v-if="row.status!=='ACTIVE'" class="btn primary small" @click="activatePolicy(row)"><Play :size="14"/>启用自动调度</button><button v-else class="btn small" @click="deactivatePolicy(row)"><Pause :size="14"/>停用调度</button><button class="btn small" :disabled="loading" @click="simulatePolicy(row)"><BarChart3 :size="14"/>模拟</button><button class="icon-btn" title="编辑策略" @click="editPolicy(row)"><Pencil :size="15"/></button><button class="icon-btn danger" title="删除策略" @click="removePolicy(row)"><Trash2 :size="15"/></button></footer></article></div>
          <PaginationBar v-model:page="page" v-model:page-size="pageSize" :total="filteredCount(data.policies)"/>
        </template>

        <template v-else-if="route==='/scheduling'">
          <div class="page-head"><div><h1>调度运行</h1><span>按目标分组查看实际参与账号与优先级</span></div><button class="btn" @click="runAutomation"><Play :size="16"/>立即评估</button></div>
          <div class="scheduling-tabs" role="tablist"><button :class="{active:schedulingTab==='status'}" @click="schedulingTab='status'">分组调度队列</button><button :class="{active:schedulingTab==='history'}" @click="schedulingTab='history'">执行记录</button></div>
          <template v-if="schedulingTab==='status'">
            <section class="schedule-overview"><div><span>参与调度</span><strong>{{ schedulingRunningCount }}</strong><small>共 {{ data.scheduling.length }} 个托管账号</small></div><div><span>当前展示分组</span><strong>{{ visibleSchedulingGroups.length }}</strong><small>{{ visibleSchedulingSections.filter(group=>!group.running.length).length }} 个暂无可用账号</small></div><div><span>快速恢复</span><strong>{{ schedulingRecoveringCount }}</strong><small>最快每 15 秒复检</small></div><label><span>查看目标分组</span><select v-model="schedulingGroup"><option value="all">全部展示分组</option><option v-for="group in visibleSchedulingGroups" :key="group.id" :value="group.id">{{ group.name }}</option></select></label></section>
            <section v-if="hiddenSchedulingSections.length" class="schedule-hidden-panel">
              <header><button class="schedule-hidden-toggle" :aria-expanded="showHiddenSchedulingGroups" @click="showHiddenSchedulingGroups=!showHiddenSchedulingGroups"><EyeOff :size="17"/><span><strong>已隐藏 {{ hiddenSchedulingSections.length }} 个分组</strong><small>不在调度主页面展示，不影响实际调度</small></span><component :is="showHiddenSchedulingGroups?ChevronDown:ChevronRight" :size="17"/></button><button class="btn small" @click="restoreAllSchedulingGroups"><Eye :size="14"/>全部恢复</button></header>
              <div v-if="showHiddenSchedulingGroups" class="schedule-hidden-list"><article v-for="group in hiddenSchedulingSections" :key="group.id"><div><strong>{{ group.name }}</strong><small>{{ group.targetName }} · {{ group.running.length }} / {{ group.running.length+group.stopped.length }} 参与</small></div><button class="btn small" @click="restoreSchedulingGroup(group.id)"><Eye :size="14"/>恢复显示</button></article></div>
            </section>
            <StateBlock v-if="!loading&&!schedulingSections.length" :title="hiddenSchedulingSections.length&&!visibleSchedulingGroups.length?'所有分组都已隐藏':'没有符合条件的目标分组'"/>
            <div v-else class="schedule-groups">
              <section v-for="group in schedulingPagedSections" :key="group.id" :class="['schedule-group',{'is-empty':!group.running.length}]">
                <header class="schedule-group-head"><div class="schedule-group-title"><span class="schedule-group-status"><span :class="['status-dot',group.running.length?'online':'offline']"/></span><div><h2>{{ group.name }}</h2><small>{{ group.targetName }} · {{ group.policyName||'未配置启用策略' }}</small></div></div><div class="schedule-group-count"><strong>{{ group.running.length }}</strong><span>/ {{ group.running.length+group.stopped.length }} 参与</span></div><span v-if="!group.running.length" class="schedule-outage"><AlertTriangle :size="15"/>{{ schedulingOutageText(group) }}</span><button class="icon-btn schedule-hide-button" title="从主页面隐藏该分组" :aria-label="`隐藏分组 ${group.name}`" @click="hideSchedulingGroup(group.id)"><EyeOff :size="16"/></button></header>
                <div v-if="group.running.length" class="schedule-running"><div class="schedule-columns"><span>优先级</span><span>参与账号</span><span>来源渠道</span><span>倍率</span><span>验证状态</span></div><div v-for="row in group.running" :key="row.managedAccountId" class="schedule-account"><strong class="priority-rank">#{{ row.priority }}</strong><div class="schedule-account-name"><strong>{{ row.remoteName }}</strong><small>{{ row.syncStatus==='SYNCED'?'已同步到目标节点':statusText(row.syncStatus) }}</small></div><div><strong>{{ row.sourceName }}</strong><small>{{ row.sourceGroup }}</small></div><div><strong>{{ ratio(row.sourceMultiplier) }}</strong><small>上限 {{ ratio(row.targetMultiplier) }}</small></div><div><span :class="['badge',row.eligible?'success':'warning']">{{ row.eligible?'参与中':'等待停止' }}</span><small>{{ row.samples }} 个样本 · {{ row.successRate==null?'--':`${Number(row.successRate).toFixed(1)}%` }}</small></div></div></div>
                <div v-else class="schedule-empty-running"><strong>当前没有账号参与这个分组的调度</strong><small>系统会优先复检可恢复候选；明确故障、人工暂停或倍率越界的账号不会强制加入。</small></div>
                <button v-if="group.stopped.length" class="schedule-stopped-toggle" :aria-expanded="expandedSchedulingGroups.has(group.id)" @click="toggleSchedulingGroup(group.id)"><span>{{ expandedSchedulingGroups.has(group.id)?'收起':'查看' }} {{ group.stopped.length }} 个未参与账号</span><small v-if="group.stopped.some(row=>row.fastValidation)">{{ group.stopped.filter(row=>row.fastValidation).length }} 个正在快速验证</small><component :is="expandedSchedulingGroups.has(group.id)?ChevronDown:ChevronRight" :size="17"/></button>
                <div v-if="expandedSchedulingGroups.has(group.id)" class="schedule-stopped-list"><div v-for="row in group.stopped" :key="row.managedAccountId" class="schedule-stopped-account"><div><strong>{{ row.remoteName }}</strong><small>{{ row.sourceName }} / {{ row.sourceGroup }}</small></div><div class="schedule-validation"><span v-if="row.fastValidation" class="badge warning">快速验证</span><span v-else class="badge neutral">未参与</span><small v-if="row.fastValidation">最近成功 {{ row.recentSuccesses }}/3 · 每 {{ row.fastProbeIntervalSeconds }} 秒 · {{ validationEta(row) }}</small><small v-else>{{ row.samples }} / {{ row.minSamples||'--' }} 个样本</small></div><p>{{ schedulingReason(row) }}</p></div></div>
              </section>
            </div>
            <PaginationBar v-if="!loading&&schedulingSections.length" v-model:page="page" v-model:page-size="pageSize" :total="schedulingSections.length"/>
          </template>
          <template v-else><StateBlock v-if="!loading&&!filtered(data.actions).length" title="暂无调度执行记录"/><div v-else class="table-wrap"><table><thead><tr><th>托管账号</th><th>来源 → 目标分组</th><th>动作</th><th>变更</th><th>判定依据</th><th>同步结果</th><th>执行时间</th></tr></thead><tbody><tr v-for="row in paged(data.actions)" :key="row.id"><td><strong>{{ row.remoteName||'账号已删除' }}</strong><small>{{ row.targetName||row.managedAccountId||'--' }}</small></td><td><strong>{{ row.sourceName }} / {{ row.sourceGroup }}</strong><small>→ {{ row.targetGroup||'未关联分组' }}</small></td><td><strong>{{ actionTitle(row) }}</strong></td><td><strong>{{ actionChange(row) }}</strong></td><td>{{ row.reason }}</td><td><span :class="['badge',statusTone(row.status)]">{{ statusText(row.status) }}</span><small v-if="row.error" class="danger-text">{{ row.error }}</small><small v-else-if="row.status==='EXECUTED'">已同步到目标节点</small></td><td>{{ date(row.executedAt||row.createdAt) }}</td></tr></tbody></table></div><PaginationBar v-if="!loading&&filtered(data.actions).length" v-model:page="page" v-model:page-size="pageSize" :total="filteredCount(data.actions)"/></template>
        </template>

        <template v-else-if="route==='/events'">
          <div class="page-head"><div><h1>事件中心</h1><span>{{ data.events.filter(x=>x.status!=='RESOLVED').length }} 个活动事件 · 恢复后自动关闭</span></div></div>
          <div class="event-list"><article v-for="row in paged(data.events)" :key="row.id" :class="['event',row.severity.toLowerCase()]" ><span class="severity">{{ row.severity }}</span><div><header><strong>{{ row.title }}</strong><span :class="['badge',statusTone(row.status)]">{{ statusText(row.status) }}</span></header><p>{{ row.detail }}</p><small>{{ eventCategoryLabel(row.category) }} · {{ date(row.createdAt) }}</small></div></article></div>
          <PaginationBar v-model:page="page" v-model:page-size="pageSize" :total="filteredCount(data.events)"/>
        </template>

        <template v-else-if="route==='/audit'">
          <div class="page-head"><div><h1>审计日志</h1><span>追加写入，不可修改</span></div></div><div class="table-wrap"><table><thead><tr><th>时间</th><th>动作</th><th>对象</th><th>对象 ID</th><th>详情</th></tr></thead><tbody><tr v-for="row in paged(data.audit)" :key="row.id"><td>{{ date(row.createdAt) }}</td><td><strong>{{ row.action }}</strong></td><td>{{ row.objectType }}</td><td><code>{{ row.objectId }}</code></td><td><code>{{ JSON.stringify(row.detail) }}</code></td></tr></tbody></table></div>
          <PaginationBar v-model:page="page" v-model:page-size="pageSize" :total="filteredCount(data.audit)"/>
        </template>

        <template v-else-if="route==='/settings'">
          <div class="page-head"><div><h1>系统设置</h1><span>{{ data.settings.buildType }} · {{ data.settings.githubRepo }}</span></div><button class="btn primary" @click="saveSettings"><Check :size="16"/>保存设置</button></div>
          <div class="settings-layout"><section class="settings-section"><header><ShieldCheck :size="20"/><div><h2>安全闸门</h2></div></header><label class="toggle-row"><div><strong>影子模式</strong><small>开启时自动策略只评估，不写入目标节点</small></div><input v-model="data.settings.shadow_mode" type="checkbox"/><span/></label><label class="toggle-row danger-row"><div><strong>紧急冻结</strong><small>保存后阻止全部远程写动作</small></div><input v-model="data.settings.emergency_freeze" type="checkbox"/><span/></label></section>
	          <section class="settings-section"><header><Activity :size="20"/><div><h2>采集与判定</h2></div></header><div class="form-grid"><label><span>探测周期（秒）</span><input v-model="data.settings.probe_interval_seconds" type="number" min="60"/></label><label><span>扫描周期（秒）</span><input v-model="data.settings.scan_interval_seconds" type="number" min="60"/></label><label><span>确认失败次数</span><input v-model="data.settings.confirmation_failures" type="number" min="1"/></label><label><span>指标窗口（分钟）</span><input v-model="data.settings.metric_window_minutes" type="number" min="1"/></label><label><span>最少异常样本</span><input v-model="data.settings.min_error_samples" type="number" min="1"/></label><label><span>异常率阈值（%）</span><input v-model="data.settings.error_rate_threshold" type="number" min="1" max="100"/></label></div></section>
	          <section class="settings-section probe-model-settings"><header><Bot :size="20"/><div><h2>分组测试模型</h2></div></header><div class="probe-model-list"><label v-for="group in data.settings.probe_groups||[]" :key="group.id"><span><strong>{{ group.name }}</strong><small>{{ group.targetName }}</small></span><select v-model="group.probeModel" required><option v-for="model in group.models" :key="model" :value="model">{{ model }}</option></select></label></div></section>
	          <section class="settings-section balance-alert-settings"><header><CircleDollarSign :size="20"/><div><h2>余额预警</h2><small>按实际余额消耗速度预测耗尽时间</small></div></header><div class="form-grid three"><label><span>工作时段提前（小时）</span><input v-model="data.settings.balance_alert_work_hours" type="number" min="1" max="168"/></label><label><span>夜间提前（小时）</span><input v-model="data.settings.balance_alert_night_hours" type="number" min="1" max="168"/></label><label><span>周末提前（小时）</span><input v-model="data.settings.balance_alert_weekend_hours" type="number" min="1" max="168"/></label></div><div class="alert-policy-summary"><span><strong>预测确认</strong><small>连续 2 次扫描低于预警线才发送，过滤短时峰值</small></span><span><strong>立即告警</strong><small>余额为 0 或源站明确返回余额不足时立即 P0</small></span><span><strong>稳定恢复</strong><small>充值立即恢复；普通波动连续 2 次稳定后恢复</small></span></div></section>
	          <section class="settings-section email-scene-settings"><header><BellRing :size="20"/><div><h2>邮件场景</h2><small>只发送你开启的业务场景；单渠道短时失败仅在页面展示</small></div></header><div class="email-scene-grid"><label class="toggle-row"><div><strong>余额不足或即将耗尽</strong><small>余额耗尽和预计不足；恢复邮件由下方总开关控制</small></div><input v-model="data.settings.email_alert_source_balance" type="checkbox"/><span/></label><label class="toggle-row"><div><strong>数据源扫描失败</strong><small>无法刷新余额、源分组或倍率</small></div><input v-model="data.settings.email_alert_source_scan" type="checkbox"/><span/></label><label class="toggle-row"><div><strong>目标节点同步失败</strong><small>无法获取目标分组、倍率或账号状态</small></div><input v-model="data.settings.email_alert_target_sync" type="checkbox"/><span/></label><label class="toggle-row"><div><strong>目标分组无人可调度</strong><small>整个分组没有任何可参与调度的账号</small></div><input v-model="data.settings.email_alert_group_availability" type="checkbox"/><span/></label><label class="toggle-row"><div><strong>远程调度写入失败</strong><small>账号启停或优先级没有写入目标节点</small></div><input v-model="data.settings.email_alert_action_execution" type="checkbox"/><span/></label><label class="toggle-row"><div><strong>账号平台校正失败</strong><small>托管账号格式与目标分组平台不一致且自动修复失败</small></div><input v-model="data.settings.email_alert_platform_sync" type="checkbox"/><span/></label><label class="toggle-row"><div><strong>故障恢复通知</strong><small>已开启场景恢复后，再发一封明确的恢复结果</small></div><input v-model="data.settings.email_alert_recovery" type="checkbox"/><span/></label></div></section>
          <section class="settings-section update-settings"><header><Download :size="20"/><div><h2>在线更新</h2><small>从 GitHub Release 安装正式版本</small></div><button class="btn small" :disabled="updateBusy||!systemVersion.updateSupported" @click="checkUpdate"><RefreshCw :size="14" :class="{spinning:updateBusy}"/>检查更新</button></header><div class="version-grid"><div><span>当前版本</span><strong>v{{ systemVersion.currentVersion||appVersion }}</strong><small>{{ systemVersion.buildType==='release'?'正式构建':'开发构建' }}</small></div><div><span>最新版本</span><strong>{{ updateInfo.latestVersion?`v${updateInfo.latestVersion}`:'尚未检查' }}</strong><small>{{ updateInfo.hasUpdate?'发现可用更新':updateInfo.latestVersion?'当前已是最新版本':systemVersion.repository }}</small></div></div><div v-if="updateInfo.latestVersion" class="release-note"><strong>{{ updateInfo.name||`渠道管家 v${updateInfo.latestVersion}` }}</strong><p>{{ updateInfo.body||'该版本没有更新说明' }}</p></div><div class="update-actions"><button v-if="updateInfo.hasUpdate&&!updateReady" class="btn primary" :disabled="updateBusy" @click="installUpdate"><Download :size="15"/>{{ updateBusy?'正在下载并安装':'下载并安装' }}</button><button v-if="updateReady" class="btn primary" :disabled="updateBusy||!systemVersion.restartSupported" @click="restartUpdatedService"><RefreshCw :size="15"/>立即重启</button><button v-if="systemVersion.rollbackAvailable" class="btn" :disabled="updateBusy" @click="rollbackUpdate">回滚上一版本</button></div></section>
	          <section class="settings-section notification-settings"><header><UserCog :size="20"/><div><h2>收件邮箱</h2><small>配置实际接收上述场景通知的邮箱</small></div><button class="btn primary small" @click="open('notification')"><Plus :size="14"/>添加</button></header><StateBlock v-if="!data.notifications.length" title="暂无通知渠道"/><div v-else class="notification-list"><div v-for="row in data.notifications" :key="row.id"><div><strong>{{ row.name }}</strong><small>{{ row.recipientHint }} · {{ row.lastTestAt?date(row.lastTestAt):'未测试' }}</small></div><span :class="['badge',statusTone(row.status)]">{{ statusText(row.status) }}</span><button class="btn small" @click="testNotification(row)">测试</button></div></div></section></div>
        </template>
      </main>
    </section>
    <button v-if="mobileOpen" class="mobile-backdrop" title="关闭导航" aria-label="关闭导航" @click="mobileOpen=false"/><aside v-if="mobileOpen" id="mobile-navigation" class="mobile-drawer" role="dialog" aria-modal="true" aria-label="主导航"><header class="brand"><span class="brand-mark"><img src="/brand/channel-manager-logo.png" alt="" /></span><strong>渠道管家</strong><button class="icon-btn" title="关闭" @click="mobileOpen=false"><X :size="18"/></button></header><nav><section v-for="group in nav" :key="group.label"><span class="nav-group-label">{{ group.label }}</span><a v-for="([path,label,Icon]) in group.items" :key="path" :href="`#${path}`" :class="{active:route===path}" :aria-current="route===path?'page':undefined"><component :is="Icon" :size="18"/>{{ label }}</a></section></nav></aside>
  </div>

  <ModalShell v-if="modal==='source'" title="接入数据源" @close="close"><form class="modal-form" @submit.prevent="createSource"><label><span>平台名称</span><input v-model="form.name" required/></label><label><span>平台类型</span><select v-model="form.platform" @change="form.authMode='PASSWORD'"><option value="SUB2API">Sub2API</option><option value="NEW_API">New API</option></select></label><label class="full"><span>平台地址</span><input v-model="form.baseURL" type="url" placeholder="https://" required/></label><fieldset v-if="form.platform==='SUB2API'" class="auth-mode full"><legend>认证方式</legend><label :class="{active:form.authMode==='PASSWORD'}"><input v-model="form.authMode" type="radio" value="PASSWORD"/><span>账号密码</span></label><label :class="{active:form.authMode==='TOKEN'}"><input v-model="form.authMode" type="radio" value="TOKEN"/><span>Access Token + RT</span></label></fieldset><template v-if="form.platform!=='SUB2API'||form.authMode!=='TOKEN'"><label><span>{{ form.platform==='SUB2API'?'管理员邮箱':'用户名' }}</span><input v-model="form.username" :type="form.platform==='SUB2API'?'email':'text'" required/></label><label><span>密码</span><input v-model="form.password" type="password" required/></label></template><template v-else><label><span>Access Token</span><input v-model="form.accessToken" type="password" autocomplete="off" required/></label><label><span>Refresh Token (RT)</span><input v-model="form.refreshToken" type="password" autocomplete="off" required/></label></template><label><span>余额 / 倍率换算</span><span class="ratio-input"><input v-model="form.valueNumerator" type="number" min="0.00000001" step="any" required/><b>:</b><input v-model="form.valueDenominator" type="number" min="0.00000001" step="any" required/></span></label><label><span>扫描周期（秒）</span><input v-model="form.interval" type="number" min="60"/></label><footer class="full"><button type="button" class="btn" @click="close">取消</button><button class="btn primary" :disabled="loading">保存</button></footer></form></ModalShell>
  <ModalShell v-if="modal==='source-edit'" title="编辑数据源" @close="close"><form class="modal-form" @submit.prevent="updateSource"><label class="full"><span>平台名称</span><input v-model="form.name" required/></label><label class="full"><span>平台地址</span><input v-model="form.baseURL" disabled/></label><label><span>余额 / 倍率换算</span><span class="ratio-input"><input v-model="form.valueNumerator" type="number" min="0.00000001" step="any" required/><b>:</b><input v-model="form.valueDenominator" type="number" min="0.00000001" step="any" required/></span></label><label><span>扫描周期（秒）</span><input v-model="form.interval" type="number" min="60"/></label><label class="check-row full"><input v-model="form.reauth" type="checkbox"/><span><strong>更新远端认证</strong><small>{{ form.platform==='SUB2API'?'遇到滑块验证或会话上限时，处理源站后在这里换新令牌':'更新源站用户名和密码后重新扫描' }}</small></span></label><template v-if="form.reauth"><fieldset v-if="form.platform==='SUB2API'" class="auth-mode full"><legend>认证方式</legend><label :class="{active:form.authMode==='PASSWORD'}"><input v-model="form.authMode" type="radio" value="PASSWORD"/><span>账号密码</span></label><label :class="{active:form.authMode==='TOKEN'}"><input v-model="form.authMode" type="radio" value="TOKEN"/><span>Access Token + RT</span></label></fieldset><template v-if="form.platform!=='SUB2API'||form.authMode==='PASSWORD'"><label><span>{{ form.platform==='SUB2API'?'管理员邮箱':'用户名' }}</span><input v-model="form.username" :type="form.platform==='SUB2API'?'email':'text'" required/></label><label><span>密码</span><input v-model="form.password" type="password" required/></label></template><template v-else><label><span>Access Token</span><input v-model="form.accessToken" type="password" autocomplete="off" required/></label><label><span>Refresh Token (RT)</span><input v-model="form.refreshToken" type="password" autocomplete="off" required/></label></template></template><footer class="full"><button type="button" class="btn" @click="close">取消</button><button class="btn primary" :disabled="loading">保存</button></footer></form></ModalShell>
  <ModalShell v-if="modal==='source-detail'&&sourceDetail" :title="sourceDetail.source.name" wide @close="close">
    <form class="mapping-workspace" @submit.prevent="deploySourceGroups">
      <div class="mapping-context">
        <div><Database :size="18"/><span><small>数据源</small><strong>{{ sourceDetail.source.name }}</strong></span></div>
        <ArrowRight :size="18"/>
        <div><Network :size="18"/><span><small>目标节点</small><strong>{{ selectedTarget?.name||'尚未选择' }}</strong></span></div>
        <span class="mapping-cardinality">1 个源分组 : N 个独立账号</span>
      </div>
      <div v-if="activeDeploymentJob" class="message warning mapping-job-status"><span class="spinner"/><span><strong>后台创建中 · {{ activeDeploymentJob.progressDone }}/{{ activeDeploymentJob.progressTotal }} 个源分组</strong><small>可以关闭页面，任务会继续运行；完成后这里会自动刷新</small></span></div>
      <div v-else-if="latestDeploymentJob?.status==='FAILED'" class="message error mapping-job-status"><AlertTriangle :size="16"/><span><strong>上次后台创建失败</strong><small>{{ latestDeploymentJob.error }}</small></span></div>
      <div class="mapping-builder">
        <section class="mapping-step">
          <header><span class="step-index">1</span><div><h3>选择源分组</h3><small>每个源分组为每个目标分组创建独立账号</small></div><button type="button" class="btn small" @click="toggleSourceGroups"><Check :size="14"/>全选可用</button></header>
          <div class="source-option-list">
            <label v-for="group in sourceDetail.groups" :key="group.id" class="source-option" :class="{selected:form.sourceGroupIDs?.includes(group.id),mapped:isGroupMapped(group)}">
              <input v-model="form.sourceGroupIDs" type="checkbox" :value="group.id" :disabled="isGroupMapped(group)" :aria-label="`选择 ${group.name}`"/>
              <span class="source-option-copy"><strong>{{ group.name }}</strong><small>{{ group.description||`远端 ID ${group.remoteId}` }}</small></span>
              <span class="source-option-meta"><b :class="{missing:group.multiplier==null}">{{ multiplierLabel(group.multiplier) }}</b><small v-if="isGroupMapped(group)">已映射到 {{ selectedTarget?.name }}</small><small v-else-if="group.deployments?.length">另有 {{ mappedTargets(group) }}</small></span>
            </label>
          </div>
        </section>
        <section class="mapping-step">
          <header><span class="step-index">2</span><div><h3>选择目标分组</h3><small>每个目标分组对应一个独立托管账号</small></div></header>
          <label class="target-node-select"><span>目标节点</span><select v-model="form.targetID" required @change="loadTargetGroups"><option value="" disabled>请选择</option><option v-for="item in writableTargets" :key="item.id" :value="item.id">{{ item.name }}</option></select></label>
          <div class="target-group-head"><span>目标分组 <b>{{ form.targetGroupIDs?.length||0 }}/{{ targetGroups.length }}</b></span><button v-if="targetGroups.length" type="button" class="btn small" @click="toggleTargetGroups"><Check :size="14"/>全选</button></div>
          <div class="target-option-list">
			<div v-if="targetGroupsLoading" class="empty-inline loading-inline"><span class="spinner"/>正在刷新目标分组</div><div v-else-if="!form.targetID" class="empty-inline">请先选择目标节点</div><div v-else-if="!targetGroups.length" class="empty-inline">该节点尚未同步分组</div>
            <label v-for="group in targetGroups" :key="group.id" class="target-option" :class="{selected:form.targetGroupIDs?.includes(group.id)}"><input v-model="form.targetGroupIDs" type="checkbox" :value="group.id"/><span><strong>{{ group.name }}</strong><small>{{ multiplierLabel(group.multiplier) }} · {{ group.platform }} · ID {{ group.remoteId }}</small></span></label>
          </div>
        </section>
      </div>
      <section class="mapping-preview">
        <header><span class="step-index">3</span><div><h3>账号预览</h3><small>每一行都会创建一个账号，并由对应目标分组单独调度</small></div></header>
        <div v-if="!selectedSourceGroups.length||!selectedTargetGroups.length" class="mapping-preview-empty">选择两侧分组后，这里会显示最终映射关系</div>
        <div v-else class="mapping-preview-list">
          <div v-for="pair in mappingPairs" :key="pair.id" class="mapping-preview-row"><span class="preview-source"><strong>{{ pair.sourceGroup.name }}</strong><small>{{ multiplierLabel(pair.sourceGroup.multiplier) }}</small></span><ArrowRight :size="18"/><span class="preview-target"><strong>{{ pair.targetGroup.name }}</strong><small>{{ pair.targetGroup.platform }} 独立托管账号</small></span></div>
        </div>
      </section>
      <footer class="mapping-submit">
        <div class="mapping-options"><label><span>初始优先级</span><input v-model="form.priority" type="number" min="1"/></label><label><span>并发</span><input v-model="form.concurrency" type="number" min="1"/></label></div>
        <div class="mapping-submit-action"><div v-if="data.settings.shadow_mode" class="message warning"><AlertTriangle :size="16"/>当前为影子模式，关闭后才能创建</div><small v-else>将创建 {{ mappingPairs.length }} 个独立托管账号（{{ form.sourceGroupIDs?.length||0 }} 个源分组 × {{ form.targetGroupIDs?.length||0 }} 个目标分组），账号类型跟随各自目标分组</small><button class="btn primary" :disabled="deploymentBusy||activeDeploymentJob||data.settings.shadow_mode||!form.sourceGroupIDs?.length||!form.targetGroupIDs?.length"><Workflow :size="16"/>{{ deploymentBusy?'正在提交':activeDeploymentJob?'后台创建中':'确认创建' }}</button></div>
      </footer>
    </form>
  </ModalShell>
  <ModalShell v-if="modal==='target'" title="接入目标节点" @close="close"><form class="modal-form" @submit.prevent="createTarget"><label><span>节点名称</span><input v-model="form.name" required/></label><label class="full"><span>节点地址</span><input v-model="form.baseURL" type="url" placeholder="https://" required/></label><label><span>管理员邮箱</span><input v-model="form.username" type="email" required/></label><label><span>管理员密码</span><input v-model="form.password" type="password" required/></label><label class="check-row full"><input v-model="form.writeEnabled" type="checkbox"/><span><strong>允许创建和维护托管账号</strong><small>仅操作本系统创建的托管账号</small></span></label><footer class="full"><button type="button" class="btn" @click="close">取消</button><button class="btn primary">保存</button></footer></form></ModalShell>
  <ModalShell v-if="modal==='target-edit'" title="编辑目标节点" @close="close"><form class="modal-form" @submit.prevent="updateTarget"><label class="full"><span>节点名称</span><input v-model="form.name" required/></label><label class="full"><span>节点地址</span><input v-model="form.baseURL" disabled/></label><label><span>管理员邮箱（不修改可留空）</span><input v-model="form.username" type="email" autocomplete="username"/></label><label><span>管理员密码（不修改可留空）</span><input v-model="form.password" type="password" autocomplete="new-password"/></label><label class="check-row full"><input v-model="form.writeEnabled" type="checkbox"/><span><strong>允许创建和维护托管账号</strong><small>仅操作本系统创建的托管账号</small></span></label><div v-if="error" class="message error full" role="alert"><AlertTriangle :size="16"/>{{ error }}</div><footer class="full"><button type="button" class="btn" @click="close">取消</button><button class="btn primary" :disabled="loading">保存并同步</button></footer></form></ModalShell>
  <ModalShell v-if="modal==='policy'" title="新建分组策略" @close="close"><form class="modal-form" @submit.prevent="createPolicy"><label class="full"><span>策略名称</span><input v-model="form.name" required/></label><label><span>目标节点</span><select v-model="form.targetID" required @change="loadPolicyTargetGroups"><option v-for="item in writableTargets" :key="item.id" :value="item.id">{{ item.name }}</option></select></label><label><span>目标分组</span><select v-model="form.targetGroupID" required><option value="" disabled>请选择</option><option v-for="group in policyTargetGroups" :key="group.id" :value="group.id" :disabled="configuredPolicyScopes.has(group.id)">{{ group.name }} · {{ configuredPolicyScopes.has(group.id)?'已有策略':multiplierLabel(group.multiplier) }}</option></select></label><fieldset class="auth-mode full"><legend>排序模式</legend><label :class="{active:form.mode==='PRICE'}"><input v-model="form.mode" type="radio" value="PRICE"/><span>价格优先</span></label><label :class="{active:form.mode==='SPEED'}"><input v-model="form.mode" type="radio" value="SPEED"/><span>速度优先</span></label></fieldset><label><span>倍率上限</span><input value="按目标分组自动获取（缓存 3 分钟）" disabled/></label><label><span>自动优先级</span><input value="1000 起，每档相差 100" disabled/></label><label class="check-row full"><input v-model="form.allowEqualMultiplier" type="checkbox"/><span><strong>允许等倍率账号参与</strong><small>关闭时源倍率必须严格低于目标分组倍率，避免零差价运行</small></span></label><label><span>最低成功率（%）</span><input v-model="form.minSuccessRate" type="number" min="1" max="100" required/></label><label><span>最少样本</span><input v-model="form.minSamples" type="number" min="1" required/></label><div class="message warning full"><Workflow :size="16"/>启用后自动同步账号启停状态和分档优先级；待恢复渠道最快每 15 秒复检。</div><footer class="full"><button type="button" class="btn" @click="close">取消</button><button class="btn primary" :disabled="loading">{{ loading?'正在创建':'创建' }}</button></footer></form></ModalShell>
  <ModalShell v-if="modal==='policy-edit'" title="编辑分组策略" @close="close"><form class="modal-form" @submit.prevent="updatePolicy"><label class="full"><span>策略名称</span><input v-model="form.name" required/></label><label><span>目标节点</span><input :value="form.targetName" disabled/></label><label><span>目标分组</span><input :value="form.targetGroupName" disabled/></label><fieldset class="auth-mode full"><legend>排序模式</legend><label :class="{active:form.mode==='PRICE'}"><input v-model="form.mode" type="radio" value="PRICE"/><span>价格优先</span></label><label :class="{active:form.mode==='SPEED'}"><input v-model="form.mode" type="radio" value="SPEED"/><span>速度优先</span></label></fieldset><label><span>倍率上限</span><input value="按目标分组自动获取（缓存 3 分钟）" disabled/></label><label><span>自动优先级</span><input value="1000 起，每档相差 100" disabled/></label><label class="check-row full"><input v-model="form.allowEqualMultiplier" type="checkbox"/><span><strong>允许等倍率账号参与</strong><small>关闭时源倍率必须严格低于目标分组倍率，避免零差价运行</small></span></label><label><span>最低成功率（%）</span><input v-model="form.minSuccessRate" type="number" min="1" max="100" required/></label><label><span>最少样本</span><input v-model="form.minSamples" type="number" min="1" required/></label><div class="message warning full"><Workflow :size="16"/>保存后立即按新版本重新评估；启用中的策略会继续自动调度。</div><footer class="full"><button type="button" class="btn" @click="close">取消</button><button class="btn primary" :disabled="loading">保存新版本</button></footer></form></ModalShell>
  <ModalShell v-if="modal==='policy-simulation'&&simulationResult" :title="`${simulationResult.policy.name} · 模拟结果`" wide @close="close"><div class="simulation-summary"><span><strong>{{ simulationResult.result.preview.filter(item=>item.decision==='ELIGIBLE').length }}</strong><small>符合策略</small></span><span><strong>{{ simulationResult.result.preview.filter(item=>item.decision==='REJECTED').length }}</strong><small>未通过</small></span><span><strong>{{ simulationResult.result.preview.length }}</strong><small>参与模拟账号</small></span></div><StateBlock v-if="!simulationResult.result.preview.length" title="该目标分组还没有托管账号"/><div v-else class="table-wrap inner simulation-table"><table><thead><tr><th>托管账号</th><th>来源</th><th>倍率比较</th><th>7 天验证</th><th>模拟判定</th><th>具体原因</th></tr></thead><tbody><tr v-for="row in simulationResult.result.preview" :key="row.managedAccountId"><td><strong>{{ row.remoteName }}</strong><small>{{ row.targetName }} / {{ row.targetGroup }}</small></td><td><strong>{{ row.sourceName }}</strong><small>{{ row.sourceGroup }}</small></td><td><strong>{{ ratio(row.sourceMultiplier) }} → {{ ratio(row.targetMultiplier) }}</strong><small>源倍率 / 目标上限</small></td><td><strong>{{ row.samples }} / {{ row.minSamples }} 个样本</strong><small>成功率 {{ row.successRate==null?'--':`${Number(row.successRate).toFixed(1)}%` }} / {{ row.minSuccessRate }}%</small></td><td><span :class="['badge',row.decision==='ELIGIBLE'?'success':'danger']">{{ row.decision==='ELIGIBLE'?'符合策略':'未通过' }}</span></td><td class="schedule-reason">{{ row.reasons?.length?row.reasons.join('；'):'所有条件均符合，实际运行将参与调度' }}</td></tr></tbody></table></div></ModalShell>
  <ModalShell v-if="modal==='managed-priority'" title="修改优先级" @close="close"><form class="modal-form" @submit.prevent="updateManagedPriority"><label class="full"><span>托管账号</span><input :value="form.name" disabled/></label><label class="full"><span>优先级（数字越小越优先）</span><input v-model="form.priority" type="number" min="1" max="1000000" required/></label><div v-if="error" class="message error full" role="alert"><AlertTriangle :size="16"/>{{ error }}</div><footer class="full"><button type="button" class="btn" @click="close">取消</button><button class="btn primary" :disabled="loading">保存并同步</button></footer></form></ModalShell>
  <ModalShell v-if="modal==='managed-concurrency'" title="修改并发" @close="close"><form class="modal-form" @submit.prevent="updateManagedConcurrency"><label class="full"><span>托管账号</span><input :value="form.name" disabled/></label><label class="full"><span>并发</span><input v-model="form.concurrency" type="number" min="1" max="1000000" required/></label><div v-if="error" class="message error full" role="alert"><AlertTriangle :size="16"/>{{ error }}</div><footer class="full"><button type="button" class="btn" @click="close">取消</button><button class="btn primary" :disabled="loading">保存并同步</button></footer></form></ModalShell>
  <ModalShell v-if="modal==='notification'" title="添加邮件通知" @close="close"><form class="modal-form" @submit.prevent="createNotification"><label><span>渠道名称</span><input v-model="form.name" required/></label><label><span>Resend API Key</span><input v-model="form.apiKey" type="password" required/></label><label><span>发件邮箱</span><input v-model="form.fromEmail" type="email" required/></label><label><span>收件邮箱</span><input v-model="form.toEmail" type="email" required/></label><footer class="full"><button type="button" class="btn" @click="close">取消</button><button class="btn primary">保存</button></footer></form></ModalShell>
  <ModalShell v-if="modal==='account'" title="账号与密码" @close="close"><form class="modal-form" @submit.prevent="updateAccount"><label class="full"><span>登录邮箱</span><input v-model.trim="form.email" type="email" autocomplete="username" required/></label><label class="full"><span>当前密码</span><input v-model="form.currentPassword" type="password" autocomplete="current-password" required/></label><label><span>新密码（不修改可留空）</span><input v-model="form.newPassword" type="password" autocomplete="new-password" minlength="10" maxlength="72"/></label><label><span>确认新密码</span><input v-model="form.confirmPassword" type="password" autocomplete="new-password" :required="!!form.newPassword"/></label><div v-if="error" class="message error full" role="alert"><AlertTriangle :size="16"/>{{ error }}</div><footer class="full"><button type="button" class="btn" @click="close">取消</button><button class="btn primary" :disabled="loading"><span v-if="loading" class="spinner"/>保存账号</button></footer></form></ModalShell>
</template>
