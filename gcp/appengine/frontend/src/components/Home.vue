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
    <b-jumbotron id="container">
      <template #header>
        <img id="hero_logo" src="./hero_logo.png">
      </template>
      <h3>Database for open source vulnerabilities</h3>
      <p>
        Matching vulnerabilities with affected versions of open source software
        is difficult.
      <p>
      <p>
        OSV makes this easier by providing an easily queryable
        <router-link to="list">database</router-link>.
      </p>
      <h4>Data sources</h4>
      <p>
        Data sources undergo automated bisection and impact analysis to provide
        accurate affected commit ranges and versions.
      </p>
      <p>
        Currently, this feed contains (mostly C/C++) vulnerabilities from <a
        href="https://github.com/google/oss-fuzz">OSS-Fuzz</a>. More language
        ecosystems to come soon.
      </p>
      <h3>API</h3>
      <p>
        OSV provides a simple <a
        href="https://api-docs.osv.dev/docs/api.osv.dev/g/c/Guides/Getting%20Started">API</a>
        that lets you query for vulnerabilities by a commit hash or version
        string:
      </p>

      <pre>
        curl -X POST -d \
            '{"commit": "6879efc2c1596d11a6a6ad296f80063b558d5e0f"}' \
            "https://api.osv.dev/v1/query?key=$API_KEY"
      </pre>
      <pre>
        curl -X POST -d \
            '{"version": "1.0.0", "package": {"name": "foo", "ecosystem": "bar"}' \
            "https://api.osv.dev/v1/query?key=$API_KEY"
      </pre>
      <h3>Open source</h3>
      <p>
        This is completely <a href="https://github.com/google/osv">open source</a>.
      </p>
      <h3>More info</h3>
      <p>
        More detailed documentation is available at TODO.
      </p>
    </b-jumbotron>
  </div>
</template>

<script>
export default {
  name: 'Home',
}
</script>

<!-- Add "scoped" attribute to limit CSS to this component only -->
<style scoped>
  #container {
    max-width: 1000px;
    margin: 0 auto;
  }

  #hero_logo {
    display: block;
    margin: 0 auto;
    max-width: 100%;
    width: auto;
    height: auto;
  }
</style>
