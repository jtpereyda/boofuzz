<template>
  <div id="app" class="container-fluid">
      <b-navbar toggleable="lg" type="dark" variant="dark" class="d-sm-none">
        <b-navbar-brand href="#"><img src="./assets/boo-logo-light.png" class="img-fluid" style="max-height: 3rem"></b-navbar-brand>
        <b-navbar-toggle target="nav-collapse"></b-navbar-toggle>
         <b-collapse id="nav-collapse" is-nav>
          <b-navbar-nav>
              <b-nav-item to="/" exact-active-class="active"><font-awesome-icon icon="tachometer-alt" size="lg" /> Dashboard</b-nav-item>
              <b-nav-item to="/about" exact-active-class="active"><font-awesome-icon icon="flask" size="lg" /> Testcases</b-nav-item>
            </b-navbar-nav>
          </b-collapse>
      </b-navbar>
      <div id="nav-side" class="bg-dark d-none d-sm-block" :style="{ width: sidebarWidth }">
        <img :src="logoImage" class="img-fluid" alt="boofuzz">
        <b-nav vertical pills>
          <b-nav-item to="/" exact-active-class="active"><span class="icon"><font-awesome-icon icon="tachometer-alt" size="lg" /></span><span v-show="!sidebarCollapsed"> Dashboard</span></b-nav-item>
          <b-nav-item to="/about" exact-active-class="active"><span class="icon"><font-awesome-icon icon="flask" size="lg" /></span><span v-show="!sidebarCollapsed">  Testcases</span></b-nav-item>
        </b-nav>

        <b-button id="toggle-btn" class="btn-secondary" @click="toggleSidebar"><font-awesome-icon icon="arrows-alt-h" :style="{ width: sidebarWidth }" /></b-button>
      </div>
      <div class="row mr-0" :style="{ marginLeft: sidebarWidth }" id="inner">
        <div class="col">
          <router-view/>
        </div>
      </div>
  </div>
</template>

<script>
import BooLogo from '@/assets/boo-logo-light.png'
import BooEyes from '@/assets/boo-eyes.png'

export default {

  name: 'App',
  data () {
    return {
      sidebarCollapsed: false,
      sidebarWidth: '250px',
      navPadding: '2rem'
    }
  },
  computed: {
    logoImage () {
      return this.sidebarCollapsed ? BooEyes : BooLogo
    }
  },
  methods: {
    toggleSidebar () {
      this.sidebarCollapsed = !this.sidebarCollapsed

      if (this.sidebarCollapsed) {
        this.sidebarWidth = '60px'
      } else {
        this.sidebarWidth = '250px'
      }
    }
  }
}
</script>

<style lang="scss">
// all this fuzz to get the media breakpoint. I can't even.
@import '@/scss/_variables.scss';
@import 'node_modules/bootstrap/scss/_functions.scss';
@import 'node_modules/bootstrap/scss/_variables.scss';
@import 'node_modules/bootstrap/scss/_mixins.scss';

#nav-side {
  position: fixed;
  top: 0;
  left: 0;
  height: 100%;
  transition: width 0.25s ease-in-out;
  img {
    margin-top: 9px;
    padding: 5px;
  }

  .nav-link {
    padding-left: 1rem;
    padding-right: 0;
    .icon {
      display: inline-block;
      width: 2rem;
      text-align: center;
    }
  }
}
#inner {
  transition: margin-left 0.25s ease-in-out;
}
@include media-breakpoint-down(sm) {
    #inner {
      margin-left: 0 !important;
    }
    .container-fluid {
      padding: 0;
    }
  }
#toggle-btn {
  position: fixed;
  bottom: 0;
  padding-left: 0;
  padding-right: 0;
  border-radius: 0;
  border: 0;
  transition: width 0.25s ease-in-out;
}

h1.title {
    margin-top: 1rem;
}
</style>
