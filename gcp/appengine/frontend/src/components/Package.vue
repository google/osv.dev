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
    <h1>{{ this.$route.params.package }}</h1>
    <p>Latest tag: {{ latestTag }} </p>
    <h2>Tags with vulnerabilities</h2>

    <b-table
      id="my-table"
      :fields="fields"
      :items="bugs">
      <template v-slot:cell(bugs)="data">
        <div v-for="bugId in data.value" :key="bugId">
          <router-link :to="getBugLink(bugId)">{{ bugId }}</router-link>
        </div>
      </template>
    </b-table>

  </div>
</template>

<script>
export default {
  name: 'Package',
  data() {
    return {
      latestTag: '',
      bugs: [],
      requestId: 0,
      fields: [
        {
            key: 'tag',
        },
        {
            key: 'bugs',
        },
      ]
    };
  },

  methods: {
    async makeRequest() {
      const curId = ++this.requestId;
      const response = await fetch(
          `/backend/package?package=${this.$route.params.package}`,
          { credentials: 'include' });
      if (response.status != 200) {
        this.$router.replace({name: 'notfound'});
      }

      const results = await response.json();
      if (curId != this.requestId) {
        // A newer request superseded this one.
        return;
      }

      this.latestTag = results.latestTag;
      this.bugs = results.bugs;
    },

    getBugLink(bugId) {
      return {
        name: 'vulnerability',
        params: {
          vulnId: bugId,
        },
      }
    }
  },

  watch: {
    '$route': function() {
      this.makeRequest();
    },
  },

  async mounted() {
    await this.makeRequest();
  },
}
</script>

<!-- Add "scoped" attribute to limit CSS to this component only -->
<style scoped>
.search {
  max-width: 400px;
}
</style>
