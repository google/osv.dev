---
layout: page
title: GET /v1experimental/importfindings
permalink: /get-v1-importfindings/
parent: API
nav_order: 5
---
# GET /v1experimental/importfindings/{source}
Experimental
{: .label }

Given a specific OSV.dev source, report any records that are failing import-time quality checks.

{: .no_toc }

<details open markdown="block">
  <summary>
    Table of contents
  </summary>
  {: .text-delta }
- TOC
{:toc}
</details>

## Experimental endpoint

This API endpoint is still considered experimental. It is targeted to operators
of home databases that OSV.dev imports from. We would value any and all
feedback. If you give this a try, please consider [opening an
issue](https://github.com/google/osv.dev/issues/new) and letting us know about
any pain points or highlights.

## Purpose

The purpose of this endpoint is give OSV record providers (home database
operators) a machine-readable way to reason about records they have published that
do not meet [OSV.dev's quality bar](data_quality.html) (and therefore have not been imported).

## Parameters

The only parameter you need for this API call is the source, in order to construct the URL.

`https://api.osv.dev/v1/importfindings/{source}`

The `source` value is the same as the `name` value in [`source.yaml`](https://github.com/google/osv.dev/blob/master/source.yaml)

Case Sensitivity: API requests are case-sensitive. Please ensure that you use the correct case for parameter names and values. For example, use 'ghsa' instead of 'GHSA'.

## Request sample

```bash
curl "https://api.osv.dev/v1experimental/importfindings/example"
```

## Example 200 response

```
{"invalid_records":[{"bug_id":"EX-1234","source":"example","findings":["IMPORT_FINDING_TYPE_INVALID_JSON"],"first_seen":"2024-12-19T15:18:00.945105Z","last_attempt":"2024-12-19T15:18:00.945105Z"}]}
```
