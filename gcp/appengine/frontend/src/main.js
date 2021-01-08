/**
 * Copyright 2021 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import Vue from 'vue'
import VueRouter from 'vue-router'

import App from './App.vue'
import Home from './components/Home.vue'
import List from './components/List.vue'
import NotFound from './components/NotFound.vue'
import Package from './components/Package.vue'
import Vulnerability from './components/Vulnerability.vue'

Vue.use(VueRouter);
Vue.config.productionTip = false

import { BootstrapVue } from 'bootstrap-vue'
Vue.use(BootstrapVue);

import 'bootstrap/dist/css/bootstrap.css'
import 'bootstrap-vue/dist/bootstrap-vue.css'

var mode = 'history';
if (process.env.NODE_ENV == 'development') {
  mode = 'hash';
}

const router = new VueRouter({
  mode,
  routes: [
    { path: '/', component: Home, name: 'home' },
    { path: '/list', component: List, name: 'list' },
    { path: '/404', component: NotFound, name: 'notfound' },
    { path: '/package/:package(.*)', component: Package, name: 'package' },
    { path: '/vulnerability/:vulnId', component: Vulnerability, name: 'vulnerability' },
  ],
})

new Vue({
  router,
  render: h => h(App)
}).$mount('#app')

