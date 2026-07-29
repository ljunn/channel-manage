<script setup>
import { computed } from 'vue'
import { ChevronLeft, ChevronRight } from '@lucide/vue'

const props = defineProps({
  total: { type: Number, required: true },
  page: { type: Number, required: true },
  pageSize: { type: Number, required: true },
})
const emit = defineEmits(['update:page', 'update:pageSize'])
const pages = computed(() => Math.max(1, Math.ceil(props.total / props.pageSize)))
</script>

<template>
  <nav v-if="total" class="pagination" aria-label="列表分页">
    <span class="pagination-total">共 {{ total }} 条</span>
    <label><span>每页</span><select :value="pageSize" aria-label="每页条数" @change="emit('update:pageSize', Number($event.target.value))"><option :value="15">15</option><option :value="30">30</option><option :value="50">50</option></select></label>
    <span>第 {{ page }} / {{ pages }} 页</span>
    <div class="pagination-actions"><button class="icon-btn" title="上一页" :disabled="page <= 1" @click="emit('update:page', page - 1)"><ChevronLeft :size="17"/></button><button class="icon-btn" title="下一页" :disabled="page >= pages" @click="emit('update:page', page + 1)"><ChevronRight :size="17"/></button></div>
  </nav>
</template>

<style scoped>
.pagination { min-height: 48px; display: flex; align-items: center; justify-content: flex-end; gap: 12px; margin-top: 10px; padding: 7px 10px; border-top: 1px solid var(--line); color: var(--muted); font-size: 12px; }
.pagination-total { margin-right: auto; }
.pagination label, .pagination-actions { display: flex; align-items: center; gap: 7px; }
.pagination select { height: 32px; padding: 0 28px 0 9px; border: 1px solid var(--line); border-radius: 6px; background: var(--paper); color: var(--ink); }
.pagination .icon-btn { width: 34px; height: 34px; }
@media (max-width: 560px) {
  .pagination { flex-wrap: wrap; justify-content: space-between; gap: 8px; padding-inline: 4px; }
  .pagination-total { margin-right: 0; }
  .pagination > span:nth-of-type(2) { order: 4; width: 100%; text-align: center; }
}
</style>
