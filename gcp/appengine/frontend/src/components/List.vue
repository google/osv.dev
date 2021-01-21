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
    <div class="search">
      <div class="mt-2">
        <b-form-input v-model="queryParam" placeholder="Package or ID search"></b-form-input>
      </div>
      <div class="mt-2">
        <b-form-checkbox
            v-model="affectedOnly"
            name="affectedOnly">
          With affected versions only
        </b-form-checkbox>
      </div>
    </div>
    <div class="mt-2">
      <b-pagination
          v-model="currentPage"
          :total-rows="total"
          :per-page="16"
          aria-controls="my-table"
      ></b-pagination>
    </div>

    <b-table
      id="my-table"
      :tbody-tr-class="rowClass"
      :fields="fields"
      :items="items">
      <template v-slot:cell(id)="vulnId">
        <router-link :to="getVulnerabilityLink(vulnId.value)">{{ vulnId.value }}</router-link>
      </template>
      <template v-slot:cell(package)="package_data">
        <a :href="getPackageLink(package_data.value)">{{ formatPackage(package_data.value) }}</a>
      </template>
      <template v-slot:cell(summary)="summary">
        <p>
          {{summary.value}}
          <router-link :to="getVulnerabilityLink(summary.item.id)">(Details)</router-link>
        </p>
      </template>
      <template v-slot:cell(affected)="data">
        <div v-for="affected in data.value.slice(0, 8)" :key="affected">
          {{affected.tag}}
        </div>
        <div v-if="data.value.length > 8" v-b-popover.hover.right="formatLongAffected(data.value.slice(8))">
          ...
        </div>
        <div v-if="data.value.length == 0">
          No impacted versions.
        </div>
      </template>
    </b-table>
  </div>
</template>

<script>
import helpers from '../mixins/helpers'

export default {
  name: 'List',
  mixins: [helpers],
  data() {
    return {
      // Set to a high limit to allow page numbers from url param to be set
      // before results are loaded.
      total: 1000000,
      items: [],
      requestId: 0,
      changeId: 0,
      fields: [
        {
            key: 'id',
            label: 'ID',
        },
        {
            key: 'package',
        },
        {
            key: 'summary',
            label: 'Summary',
        },
        {
            key: 'affected',
        },
      ]
    };
  },

  methods: {
    async makeRequest() {
      const curId = ++this.requestId;
      const response = await fetch(
          `/backend/query?page=${this.currentPage}&search=${this.queryParam}&affected_only=${this.affectedOnly}`,
          { credentials: 'include' });

      const results = await response.json();
      if (curId != this.requestId) {
        // A newer request superseded this one.
        return;
      }

      this.total = results.total;
      this.items = results.items;
    },

    getParams() {
      return {
        q: this.queryParam,
        affected_only: this.affectedOnly,
        page: this.currentPage
      };
    },

    formatLongAffected(affected) {
      const tags = [];
      for (const entry of affected) {
        tags.push(entry.tag);
      }

      return tags.join(' ');
    },

    getVulnerabilityLink(vulnId) {
      return {
        name: 'vulnerability',
        params: {
          vulnId,
        },
      };
    },

    rowClass(item, type) {
      if (!item || type !== 'row') return '';
      if (!item.isFixed) return 'not_fixed';

      return '';
    },
  },

  watch: {
    '$route': function() {
      this.makeRequest();
    },
  },

  computed: {
    affectedOnly: {
      get() {
        return this.$route.query.affected_only || true;
      },

      set(value) {
        this.$router.replace({path: this.$route.path, query: { ...this.getParams(), affected_only: value } });
      }
    },

    currentPage: {
      get() {
        return this.$route.query.page || 1;
      },

      set(value) {
        this.$router.replace({path: this.$route.path, query: { ...this.getParams(), page: value } });
      }
    },

    queryParam: {
      get() {
        return this.$route.query.q || '';
      },

      set(value) {
        const curId = ++this.changeId;
        setTimeout(
          () => {
            if (curId == this.changeId) {
              this.$router.replace({path: this.$route.path, query: { ...this.getParams(), q: value, page: 1 } });
            }
          },
          600
        );
      }
    },
  },

  async mounted() {
    await this.makeRequest();
  },
}
</script>

<!-- Add "scoped" attribute to limit CSS to this component only -->
<style>
.search {
  max-width: 400px;
}

.not_fixed {
  background-color: #ffebeb;
}
</style>
