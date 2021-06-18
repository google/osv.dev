<!--
 Copyright 2021 Google LLC

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
-->

<template>
  <div>
    <b-navbar id="navbar" toggleable="lg" type="dark">
      <b-navbar-brand to="/">
        <img src="./logo.png" width="200">
      </b-navbar-brand>
      <b-navbar-toggle target="nav-collapse"></b-navbar-toggle>

      <b-collapse id="nav-collapse" is-nav>
        <b-navbar-nav>
          <b-nav-item to="/list">Vulnerability list</b-nav-item>
          <b-nav-item href="/docs/">API & Docs</b-nav-item>
        </b-navbar-nav>
        <b-navbar-nav class="ml-auto">
          <b-nav-item href="https://github.com/google/osv">GitHub</b-nav-item>
        </b-navbar-nav>
      </b-collapse>
    </b-navbar>
    <div id="container">
      <router-view></router-view>
    </div>
    <footer class="border-top py-4">
      <b-container>
        <b-row align-h="center">
          <b-col cols="2">
            <a href="https://policies.google.com/terms">Terms of Service</a>
          </b-col>
          <b-col cols="2">
            <a href="https://policies.google.com/privacy">Privacy policy</a>
          </b-col>
          <b-col cols="2">
            <a href="https://osv.dev/docs/#tag/faq">FAQ</a>
          </b-col>
        </b-row>
      </b-container>
    </footer>
  </div>
</template>

<script>

export default {
  name: 'App',
}
</script>

<style lang="scss">
  $font-family-sans-serif: 'Roboto', sans-serif;
  @import url('https://fonts.googleapis.com/css2?family=Roboto&display=swap');
  @import '~bootstrap/scss/bootstrap.scss';
  @import '~bootstrap-vue/src/index.scss';
</style>

<style scoped>
#container {
  padding: 1em;
}

#navbar {
  background-color: #161212;
}

footer {
  font-size: 12px;
}
</style>
