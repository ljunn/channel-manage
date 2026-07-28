<script setup>
defineProps({ title: String, detail: String, loading: Boolean })
</script>
<template><div class="state-block" role="status" aria-live="polite"><span v-if="loading" class="spinner" aria-hidden="true" /><strong>{{ title }}</strong><small v-if="detail">{{ detail }}</small><slot /></div></template>
