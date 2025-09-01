<template>
    <div id="fuzz-statistics">
        <b-card header-tag="header">
          <template #header>
            <h5 class="w-25 float-left mt-2">Statistics</h5>
            <b-button class="float-right" :variant="running_variant" @click="togglePause">{{ running_label }} <font-awesome-icon :icon="running_icon" /></b-button>
          </template>
          <fuzz-progress-bar :title="progress.overall.label" :max="progress.overall.max" :value="progress.overall.current" variant="success" />
          <fuzz-progress-bar :title="progress.step.label" :max="progress.step.max" :value="progress.step.current" variant="primary" />
          <div class="row mt-4 text-center">
            <div class="col-sm">
              <h3 class="mb-0">1.7 / 1.4 / 1.8</h3>
              <span>Testcases/s (1 min ⌀ / 10 min ⌀)</span>
            </div>
            <div class="col-sm">
              <h3 class="mb-0">4 Hours 53 Minutes</h3>
              <span>Estimated Time Remaining</span>
            </div>
            <div class="col-sm">
              <h3 class="mb-0">1 Hour 23 Minutes</h3>
              <span>Time spent fuzzing</span>
            </div>
          </div>
        </b-card>

        <h5 class="mt-4">Recorded Failures</h5>
        <b-table striped hover :items="crashes" :fields="crash_fields" />
    </div>
</template>

<script>
import FuzzProgressBar from './Statistics/FuzzProgressBar.vue'

export default {
  name: 'FuzzStatistics',
  components: {
    FuzzProgressBar
  },
  data () {
    return {
      progress: {
        overall: {
          label: 'Overall',
          current: 86891,
          max: 163602
        },
        step: {
          label: 'Current Step',
          current: 75,
          max: 182
        }
      },
      running: true,
      crash_fields: [
        {
          key: 'case_id',
          sortable: true,
          label: 'Test Case #'
        },
        {
          key: 'synopsis',
          sortable: false,
          label: 'Crash Synopsis'
        }
      ],
      crashes: [
        { case_id: 1, synopsis: 'ExternalMonitor#139700004031906 detected crash on test case #1: External instrumentation detects a crash...' },
        { case_id: 3, synopsis: 'ExternalMonitor#139700004031906 detected crash on test case #3: External instrumentation detects a crash...' },
        { case_id: 4, synopsis: 'ExternalMonitor#139700004031906 detected crash on test case #1: External instrumentation detects a crash...' },
        { case_id: 5, synopsis: 'ExternalMonitor#139700004031906 detected crash on test case #3: External instrumentation detects a crash...' },
        { case_id: 6, synopsis: 'ExternalMonitor#139700004031906 detected crash on test case #1: External instrumentation detects a crash...' },
        { case_id: 7, synopsis: 'ExternalMonitor#139700004031906 detected crash on test case #3: External instrumentation detects a crash...' },
        { case_id: 8, synopsis: 'ExternalMonitor#139700004031906 detected crash on test case #1: External instrumentation detects a crash...' },
        { case_id: 9, synopsis: 'ExternalMonitor#139700004031906 detected crash on test case #3: External instrumentation detects a crash...' },
        { case_id: 10, synopsis: 'ExternalMonitor#139700004031906 detected crash on test case #1: External instrumentation detects a crash...' },
        { case_id: 13, synopsis: 'ExternalMonitor#139700004031906 detected crash on test case #3: External instrumentation detects a crash...' },
        { case_id: 14, synopsis: 'ExternalMonitor#139700004031906 detected crash on test case #1: External instrumentation detects a crash...' },
        { case_id: 15, synopsis: 'ExternalMonitor#139700004031906 detected crash on test case #3: External instrumentation detects a crash...' },
        { case_id: 16, synopsis: 'ExternalMonitor#139700004031906 detected crash on test case #1: External instrumentation detects a crash...' },
        { case_id: 17, synopsis: 'ExternalMonitor#139700004031906 detected crash on test case #3: External instrumentation detects a crash...' },
        { case_id: 18, synopsis: 'ExternalMonitor#139700004031906 detected crash on test case #1: External instrumentation detects a crash...' },
        { case_id: 19, synopsis: 'ExternalMonitor#139700004031906 detected crash on test case #3: External instrumentation detects a crash...' },
        { case_id: 27, synopsis: 'ExternalMonitor#139700004031906 detected crash on test case #27: External instrumentation detects a crash...' }
      ]
    }
  },
  computed: {
    running_label () {
      return this.running ? 'Running' : 'Paused'
    },
    running_icon () {
      return this.running ? 'pause-circle' : 'play-circle'
    },
    running_variant () {
      return this.running ? 'success' : 'danger'
    }
  },
  methods: {
    togglePause () {
      // TODO: api call.
      this.running = !this.running
    }
  }
}
</script>
