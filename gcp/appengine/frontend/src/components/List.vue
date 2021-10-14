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
    <div class="d-flex flex-wrap search">
      <div class="mt-2">
        <b-form inline>
          <b-form-input class="mr-1" v-model="queryParam" placeholder="Package or ID search"></b-form-input>
          <b-form-select class="mr-1" v-model="ecosystem" :options="ecosystems"></b-form-select>
          <b-form-checkbox
              class="mr-2"
              v-model="affectedOnly"
              name="affectedOnly">
            With affected versions only
          </b-form-checkbox>
          <b-spinner variant="primary" v-show="loading"></b-spinner>
        </b-form>
      </div>
      <div class="ml-auto">
        <b-pagination
            v-model="currentPage"
            :total-rows="total"
            :per-page="16"
            aria-controls="my-table">
        </b-pagination>
      </div>
    </div>

    <b-table
      id="my-table"
      :tbody-tr-class="rowClass"
      :fields="fields"
      :items="items">
      <template v-slot:cell(id)="vulnId">
        <router-link :to="getVulnerabilityLink(vulnId.value)">{{ vulnId.value }}</router-link>
      </template>
      <template v-slot:cell(packages)="data">
        <div v-for="affected in data.item.affected" :key="affected.package.name">
          <router-link :to="getPackageLink(affected.package)">
            {{ formatPackage(affected.package) }}
          </router-link>
        </div>
      </template>
      <template v-slot:cell(summary)="summary">
        <p>
          {{getSummary(summary.value, summary.item.details)}}
          <router-link :to="getVulnerabilityLink(summary.item.id)">(Details)</router-link>
        </p>
      </template>
      <template v-slot:cell(affected)="data">
        <span v-if="hasSemVer(data.value)">
          See details.
        </span>
        <span v-else>
          <div v-for="([affected, extra], idx) in [collectVersions(data.value)]" :key="idx">
            <div v-for="version in affected" :key="version">
              {{version}}
            </div>
            <div v-if="extra.length > 0" v-b-popover.hover.right="formatLongAffected(extra)">
              ...
            </div>
          </div>
        </span>
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
      loading: false,
      ecosystems: [{
        text: 'Select ecosystem',
        value: '',
      }],
      fields: [
        {
            key: 'id',
            label: 'ID',
        },
        {
            key: 'packages',
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
      this.loading = true;
      this.items = [];
      const curId = ++this.requestId;
      const response = await fetch(
          `${process.env.VUE_APP_BACKEND}/backend/query?page=${this.currentPage}&search=${this.queryParam}&` +
          `affected_only=${this.affectedOnly}&ecosystem=${this.ecosystem}`);

      const results = await response.json();
      if (curId != this.requestId) {
        // A newer request superseded this one.
        return;
      }

      this.loading = false;
      this.total = results.total;
      this.items = results.items;
    },

    async getEcosystems() {
      const response = await fetch(`${process.env.VUE_APP_BACKEND}/backend/ecosystems`);
      this.ecosystems = [{
        text: 'Select ecosystem',
        value: '',
      }];

      const results = await response.json();
      for (let ecosystem of results) {
        this.ecosystems.push({
          text: ecosystem,
          value: ecosystem,
        });
      }
    },

    getSummary(summary, details) {
      if (summary) {
        return summary;
      }

      if (!details) {
        return 'NA';
      }

      if (details.length <= 120) {
        return details;
      }

      return details.substring(0, 120) + '...';
    },

    getParams() {
      return {
        q: this.queryParam,
        affected_only: this.affectedOnly,
        page: this.currentPage,
        ecosystem: this.ecosystem,
      };
    },

    formatLongAffected(affected) {
      return affected.join(' ');
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

    hasSemVer(affected) {
      for (let entry of affected) {
        if (!entry.ranges) continue;

        for (let range of entry.ranges) {
          if (range.type == 'SEMVER') return true;
        }
      }
      return false;
    },

    collectVersions(affected) {
      let versions = [];
      for (let entry of affected) {
        if (!entry.versions) continue;
        for (let version of entry.versions) {
          versions.push(version);
        }
      }
      return [versions.slice(0, 8), versions.slice(8)];
    }
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

    ecosystem: {
      get() {
        return this.$route.query.ecosystem || '';
      },

      set(value) {
        this.$router.replace({path: this.$route.path, query: { ...this.getParams(), ecosystem: value } });
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
    document.title = 'Vulnerability list';
    this.getEcosystems();
    await this.makeRequest();
  },
}
</script>

<!-- Add "scoped" attribute to limit CSS to this component only -->
<style>
.search {
}

.not_fixed {
  background-color: #ffebeb;
}
</style>
