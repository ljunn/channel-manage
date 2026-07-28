<script setup>
import { nextTick, onBeforeUnmount, onMounted, ref } from 'vue'
import { X } from '@lucide/vue'
defineProps({ title: { type: String, required: true }, wide: Boolean })
const emit = defineEmits(['close'])
const dialog = ref(null)
let previousFocus
let previousOverflow = ''

function focusableElements() {
  return [...(dialog.value?.querySelectorAll('a[href],button:not([disabled]),input:not([disabled]),select:not([disabled]),textarea:not([disabled]),[tabindex]:not([tabindex="-1"])') || [])]
}

function onKeydown(event) {
  if (event.key === 'Escape') {
    event.preventDefault()
    emit('close')
    return
  }
  if (event.key !== 'Tab') return
  const items = focusableElements()
  if (!items.length) {
    event.preventDefault()
    dialog.value?.focus()
    return
  }
  const [first] = items
  const last = items[items.length - 1]
  if (event.shiftKey && (document.activeElement === first || !dialog.value?.contains(document.activeElement))) {
    event.preventDefault()
    last.focus()
  } else if (!event.shiftKey && document.activeElement === last) {
    event.preventDefault()
    first.focus()
  }
}

onMounted(async () => {
  previousFocus = document.activeElement
  previousOverflow = document.body.style.overflow
  document.body.style.overflow = 'hidden'
  document.addEventListener('keydown', onKeydown)
  await nextTick()
  const items = focusableElements()
  const preferred = dialog.value?.querySelector('[autofocus],input:not([disabled]),select:not([disabled]),textarea:not([disabled])')
  ;(preferred || items[0] || dialog.value)?.focus()
})

onBeforeUnmount(() => {
  document.removeEventListener('keydown', onKeydown)
  document.body.style.overflow = previousOverflow
  previousFocus?.focus?.()
})
</script>

<template>
  <div class="modal-backdrop" @mousedown.self="emit('close')">
    <section ref="dialog" class="modal" :class="{ wide }" role="dialog" aria-modal="true" :aria-label="title" tabindex="-1">
      <header><h2>{{ title }}</h2><button class="icon-btn" title="关闭" aria-label="关闭" @click="emit('close')"><X :size="18" /></button></header>
      <div class="modal-body"><slot /></div>
    </section>
  </div>
</template>
