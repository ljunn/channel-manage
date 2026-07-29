<script setup>
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { Chart } from 'chart.js/auto'

const props = defineProps({ groups:{type:Array,required:true}, points:{type:Array,required:true}, metric:{type:String,required:true}, selectedGroup:{type:String,default:'all'} })
const canvas=ref(null)
let chart
const palette=['#117c73','#2869b9','#b63d45','#925b0b','#6956bd','#237a52','#b04a76','#426b78','#8a6830','#4f6fb0']
const activeGroups=computed(()=>props.selectedGroup==='all'?props.groups:props.groups.filter(group=>group.id===props.selectedGroup))
const metricLabels={average:'平均值',median:'中位数',minimum:'最低值'}
const endpointLabels={
  id:'endpointLabels',
  afterDatasetsDraw(chart){
    const {ctx,chartArea}=chart
    if(!chartArea)return
    const labels=[]
    chart.data.datasets.forEach((dataset,index)=>{
      const points=chart.getDatasetMeta(index).data
      const last=points?.[points.length-1]
      if(last?.x==null||last?.y==null)return
      labels.push({dataset,last,y:last.y,color:dataset.borderColor})
    })
    if(!labels.length)return
    labels.sort((left,right)=>left.y-right.y)
    const top=chartArea.top+8
    const bottom=chartArea.bottom-8
    const gap=labels.length>1?Math.min(16,(bottom-top)/(labels.length-1)):0
    labels[0].labelY=Math.max(top,labels[0].y)
    for(let index=1;index<labels.length;index++)labels[index].labelY=Math.max(labels[index].y,labels[index-1].labelY+gap)
    for(let index=labels.length-1;index>=0;index--)labels[index].labelY=Math.min(labels[index].labelY,index===labels.length-1?bottom:labels[index+1].labelY-gap)
    ctx.save()
    ctx.font='600 11px "PingFang SC", "Microsoft YaHei", sans-serif'
    ctx.textBaseline='middle'
    labels.forEach(item=>{
      const fullLabel=item.dataset.label||''
      const labelX=chartArea.right+16
      const maxWidth=chart.width-labelX-8
      let label=fullLabel
      while(label.length>2&&ctx.measureText(`${label}…`).width>maxWidth)label=label.slice(0,-1)
      if(label!==fullLabel)label+='…'
      ctx.strokeStyle=item.color
      ctx.lineWidth=1
      ctx.beginPath()
      ctx.moveTo(item.last.x,item.last.y)
      ctx.lineTo(chartArea.right+7,item.labelY)
      ctx.stroke()
      ctx.fillStyle=item.color
      ctx.textAlign='left'
      ctx.fillText(label,labelX,item.labelY)
    })
    ctx.restore()
  },
}

function render(){
  if(!canvas.value)return
  chart?.destroy()
  const datasets=activeGroups.value.map((group,index)=>({label:group.targetName?`${group.targetName} / ${group.name}`:group.name,data:props.points.filter(point=>point.targetGroupId===group.id&&point[props.metric]!=null).map(point=>({x:new Date(point.capturedAt).getTime(),y:Number(point[props.metric])})),borderColor:palette[index%palette.length],backgroundColor:palette[index%palette.length],borderWidth:2,pointRadius:2.5,pointHoverRadius:5,tension:.24,spanGaps:true}))
  const compact=window.matchMedia('(max-width: 760px)').matches
  chart=new Chart(canvas.value,{type:'line',data:{datasets},plugins:[endpointLabels],options:{responsive:true,maintainAspectRatio:false,layout:{padding:{right:compact?100:235}},interaction:{mode:'nearest',intersect:false},plugins:{legend:{display:false},tooltip:{callbacks:{label:context=>`${context.dataset.label} · ${metricLabels[props.metric]} ×${context.parsed.y.toFixed(4)}`}}},scales:{x:{type:'linear',grid:{display:false},ticks:{maxTicksLimit:compact?4:7,callback:value=>new Intl.DateTimeFormat('zh-CN',{month:'2-digit',day:'2-digit',hour:'2-digit'}).format(new Date(value))},title:{display:true,text:'时间'}},y:{beginAtZero:false,grid:{color:'#edf1f3'},ticks:{callback:value=>`×${Number(value).toFixed(2)}`},title:{display:true,text:'倍率'}}}}})
}
onMounted(render)
watch(()=>[props.points,props.metric,props.selectedGroup,props.groups],render,{deep:true})
onBeforeUnmount(()=>chart?.destroy())
</script>

<template><div class="trend-canvas"><canvas ref="canvas"/></div></template>

<style scoped>
.trend-canvas { position: relative; width: 100%; height: 360px; }
@media (max-width: 760px) { .trend-canvas { height: 300px; } }
</style>
