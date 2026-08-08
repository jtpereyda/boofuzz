<template>
    <div class="row">
      <div class="col-sm-2 text-center text-sm-right">{{ title }}</div>
      <div class="col-sm">
        <b-progress :max="max">
          <b-progress-bar :value="value" show-progress animated :variant="variant" :label="`${((value / max) * 100).toFixed(2)}%`"></b-progress-bar>
        </b-progress>
      </div>
      <div class="col-sm-2 text-center">{{ value }} / {{ max }}</div>
    </div>
</template>

<script>
export default {
  name: 'FuzzProgressBar',
  props: ['title', 'value', 'variant', 'max']
}
</script>
