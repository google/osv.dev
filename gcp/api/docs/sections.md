# What is OSV?
---

### Introduction

OSV is a vulnerability database for open source projects. It exposes an API that
lets users of these projects query whether or not their versions are impacted.

For each vulnerability, we perform bisects to figure out the exact commit that
introduces the bug, as well the exact commit that fixes it. This is cross
referenced against upstream repositories to figure out the affected tags and
commit ranges.

### How does the API work?

The API accepts a git commit hash or a version number and returns the
list of vulnerabilities that are present for that version.

### Is there a rate limit?

There is a rate limit of 100 requests/min.

### Where does the data come from?

This is currently filled with vulnerabilities found by [OSS-Fuzz] (mostly C/C++
projects). OSS-Fuzz is a continuous fuzzing service for open source software,
with over 350 open source projects integrated and has found over [25,000] bugs.
This will be extended in the future to support other vulnerability sources.

The full list of vulnerabilities can be browsed at <https://osv.dev>.

[OSS-Fuzz]: https://github.com/google/oss-fuzz
[25,000]: https://bugs.chromium.org/p/oss-fuzz/issues/list?q=-status%3AWontFix%2CDuplicate%20-component%3AInfra&can=1

# Getting Started
---

### Before you begin

1. Create a new [Cloud Platform project](https://console.developers.google.com/projectcreate).

### Creating an API key

1. [Create an API key](https://console.developers.google.com/apis/credentials) in the Google APIs Console.
2. Click **Create credentials**, then select **API key**.
3. Copy this key in clipboard and click **Close**.
4. Set the key in a helper environment variable.

```
export API_KEY=<paste api key from clipboard>
```

### Enable the API

Before you can make calls to this API, you need to enable it in the Cloud Platform project you created.
1. [View this API](https://console.developers.google.com/apis/api/api.osv.dev/overview) in the Google APIs Console.
2. Click the **Enable** button, then wait for it to complete.
3. You can now call the API using the API key you created!

### Using the API

Browse the reference section of this site to see examples of what you can do
with this API and how to use it. You can use the **Try this API** tool on the
right side of an API method page to generate a sample request.

For a quick example using curl, run:

```
curl -X POST -d '{"commit": "6879efc2c1596d11a6a6ad296f80063b558d5e0f"}' \
  "https://api.osv.dev/v1/query?key=$API_KEY"
```

