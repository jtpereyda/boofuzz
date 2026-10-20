<template>
  <div class="home">
    <h1 class="title">Fuzz Dashboard</h1>
    <fuzz-statistics />
  </div>
</template>

<script>
// @ is an alias to /src
import FuzzStatistics from '@/components/FuzzStatistics.vue'

export default {
  name: 'Home',
  components: {
    FuzzStatistics
  }
}
</script>
