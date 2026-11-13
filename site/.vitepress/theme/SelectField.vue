<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, ref } from 'vue'

const props = defineProps<{
  id: string
  label: string
  modelValue: string
  options: { value: string; label: string }[]
  hideLabel?: boolean
}>()
const emit = defineEmits<{ 'update:modelValue': [value: string] }>()
const root = ref<HTMLElement>()
const trigger = ref<HTMLButtonElement>()
const menu = ref<HTMLElement>()
const opened = ref(false)
const active = ref(0)
const above = ref(false)
const menuHeight = ref(280)
const selected = computed(() => props.options.find(option => option.value === props.modelValue))
let search = ''
let lastTyped = 0

function positionMenu() {
  const rect = trigger.value?.getBoundingClientRect()
  if (!rect) return
  const below = window.innerHeight - rect.bottom - 12
  const spaceAbove = rect.top - 12
  above.value = below < 240 && spaceAbove > below
  menuHeight.value = Math.max(44, Math.min(280, above.value ? spaceAbove : below))
}
async function open(index = props.options.findIndex(option => option.value === props.modelValue)) {
  if (!props.options.length) return
  active.value = Math.max(0, index)
  positionMenu()
  opened.value = true
  await nextTick()
  menu.value?.focus({ preventScroll: true })
  revealActive()
}
function close(restoreFocus = false) {
  opened.value = false
  search = ''
  if (restoreFocus) trigger.value?.focus({ preventScroll: true })
}
function choose(index: number) {
  const option = props.options[index]
  if (option) emit('update:modelValue', option.value)
  close(true)
}
function revealActive() {
  void nextTick(() => menu.value?.children[active.value]?.scrollIntoView({ block: 'nearest' }))
}
function onKey(event: KeyboardEvent) {
  if (event.key === 'Escape') { event.preventDefault(); close(true); return }
  if (event.key === 'Tab') { close(); return }
  if (opened.value && (event.key === 'Enter' || event.key === ' ')) {
    event.preventDefault(); choose(active.value); return
  }
  if (['ArrowDown', 'ArrowUp', 'Home', 'End'].includes(event.key)) {
    event.preventDefault()
    if (!opened.value) {
      void open(event.key === 'Home' ? 0 : event.key === 'End' ? props.options.length - 1 : undefined)
      return
    }
    active.value = event.key === 'Home' ? 0 : event.key === 'End' ? props.options.length - 1
      : (active.value + (event.key === 'ArrowDown' ? 1 : -1) + props.options.length) % props.options.length
    revealActive()
  } else if (event.key.length === 1 && !event.ctrlKey && !event.metaKey && !event.altKey && event.key !== ' ') {
    event.preventDefault()
    const now = Date.now()
    search = (now - lastTyped < 700 ? search : '') + event.key.toLocaleLowerCase()
    lastTyped = now
    const index = props.options.findIndex(option => option.label.toLocaleLowerCase().startsWith(search))
    if (index >= 0) {
      if (!opened.value) void open(index)
      else { active.value = index; revealActive() }
    }
  }
}
function outside(event: PointerEvent) {
  if (event.target instanceof Node && !root.value?.contains(event.target)) close()
}
function focusOut(event: FocusEvent) {
  if (!(event.relatedTarget instanceof Node) || !root.value?.contains(event.relatedTarget)) close()
}
onMounted(() => {
  document.addEventListener('pointerdown', outside)
  window.addEventListener('resize', positionMenu)
})
onBeforeUnmount(() => {
  document.removeEventListener('pointerdown', outside)
  window.removeEventListener('resize', positionMenu)
})
</script>

<template>
  <div ref="root" class="rl-select" @focusout="focusOut">
    <span :id="`${id}-label`" class="rl-select-label" :class="{ 'rl-sr-only': hideLabel }">{{ label }}</span>
    <button ref="trigger" type="button" class="rl-select-trigger" aria-haspopup="listbox"
      :aria-expanded="opened" :aria-controls="opened ? `${id}-menu` : undefined"
      :aria-labelledby="`${id}-label ${id}-value`" @click="opened ? close(true) : open()" @keydown="onKey">
      <span :id="`${id}-value`">{{ selected?.label }}</span>
      <svg viewBox="0 0 20 20" aria-hidden="true"><path d="m6 8 4 4 4-4" /></svg>
    </button>
    <div v-if="opened" :id="`${id}-menu`" ref="menu" role="listbox" tabindex="-1"
      class="rl-select-menu" :class="{ 'is-above': above }" :style="{ maxHeight: `${menuHeight}px` }"
      :aria-labelledby="`${id}-label`" :aria-activedescendant="`${id}-option-${active}`" @keydown="onKey">
      <div v-for="(option, index) in options" :id="`${id}-option-${index}`" :key="option.value"
        role="option" :aria-selected="option.value === modelValue" class="rl-select-option"
        :class="{ 'is-active': index === active }" @pointermove="active = index" @click="choose(index)">
        <span>{{ option.label }}</span>
        <svg v-if="option.value === modelValue" viewBox="0 0 20 20" aria-hidden="true"><path d="m4 10 4 4 8-8" /></svg>
      </div>
    </div>
  </div>
</template>

<style scoped>
.rl-select { position: relative; min-width: 0; display: grid; gap: 8px; font-size: 14px; }
.rl-select-label { line-height: 1.5; }
.rl-select-trigger { display: flex; width: 100%; min-height: 44px; align-items: center; justify-content: space-between; gap: 16px; padding: 10px 12px; border: 1px solid var(--rl-line); border-radius: 6px; background: var(--rl-bg); color: var(--rl-ink); text-align: left; font: inherit; cursor: pointer; }
.rl-select-trigger:hover, .rl-select-trigger[aria-expanded='true'] { border-color: var(--rl-muted); }
.rl-select-trigger > span { min-width: 0; overflow-wrap: anywhere; }
.rl-select svg { width: 18px; height: 18px; flex-shrink: 0; fill: none; stroke: currentColor; stroke-width: 1.5; stroke-linecap: round; stroke-linejoin: round; }
.rl-select-menu { position: absolute; z-index: 30; top: calc(100% + 6px); left: 0; width: 100%; min-width: 0; overflow-y: auto; overscroll-behavior: contain; padding: 4px; border: 1px solid var(--rl-line); border-radius: 8px; background: var(--rl-bg); color: var(--rl-ink); outline: none; }
.rl-select-menu.is-above { top: auto; bottom: calc(100% + 6px); }
.rl-select-option { display: flex; align-items: center; justify-content: space-between; gap: 12px; min-height: 40px; padding: 8px 10px; border-radius: 4px; line-height: 1.5; cursor: pointer; user-select: none; overflow-wrap: anywhere; }
.rl-select-option.is-active { background: var(--rl-surface); outline: 1px solid var(--rl-muted); outline-offset: -1px; }
.rl-select-option[aria-selected='true'] { font-weight: 650; }
</style>
