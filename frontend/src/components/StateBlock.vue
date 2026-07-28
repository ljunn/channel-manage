<script setup>
defineProps({ title: String, detail: String, loading: Boolean })
</script>
<template><div class="state-block"><span v-if="loading" class="spinner" /><strong>{{ title }}</strong><small v-if="detail">{{ detail }}</small><slot /></div></template>
