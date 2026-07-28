<script setup>
import { X } from '@lucide/vue'
defineProps({ title: { type: String, required: true }, wide: Boolean })
defineEmits(['close'])
</script>

<template>
  <div class="modal-backdrop" @mousedown.self="$emit('close')">
    <section class="modal" :class="{ wide }" role="dialog" aria-modal="true" :aria-label="title">
      <header><h2>{{ title }}</h2><button class="icon-btn" title="关闭" @click="$emit('close')"><X :size="18" /></button></header>
      <div class="modal-body"><slot /></div>
    </section>
  </div>
</template>
