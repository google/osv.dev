---
title: "API Latency Improvements and Revised SLOs"
date: 2025-10-14T11:00:00+11:00
draft: false
author: Michael Kedar
---

As more vulnerabilities are published to OSV.dev, we want to ensure our API remains fast and reliable for our users. To support this, we've rolled out a new database indexing strategy, resulting in API queries that are now up to 5x faster.

<!--more-->

## Overview

Previously, the OSV.dev API was querying and serving its records from a large database entity that contained all fields necessary to build the vulnerability JSON from. This had a couple of drawbacks:
- The whole record must be retrieved to verify if it matched a query, even it was not needed (e.g. batch queries only return the ID and modified dates).
- Reconstructing the OSV format from these potentially large entities could be costly.

Now, we are storing the complete computed OSV records directly (including with populated alias/related/upstream fields from other records), and have a secondary table containing only the affected version information of the vulnerabilities, which we perform matching against. This has some significant benefits:
- Queries by versions can be performed more efficiently, as we match against smaller entities.
- Returning the full vulnerability details is much faster by just reading the final record directly from our database, and only when needed.

These database changes allow us to serve data much more efficiently, having a significant improvement on our API's overall performance.

## API Latency Improvements

This change is now fully rolled out to production, and the impact on API latency can be seen below (solid line) compared to our old implementation (dashed line).

![Line graph of mean GET /v1/vulns/{id} latency. Before (dashed) is ~0.2s, after (solid) is ~0.04s.](getvulnbyid_mean.png "Mean latency for GET /v1/vulns/{id} dropped from ~0.2s (dashed) to ~0.04s (solid).")
![Line graph of mean POST /v1/query latency. Before (dashed) is ~0.3s, after (solid) is ~0.12s.](queryaffected_mean.png "Mean latency for POST /v1/query dropped from ~0.3s (dashed) to ~0.12s (solid).")
![Line graph of mean POST /v1/querybatch latency. Before (dashed) is ~1.8s, after (solid) is ~0.6s.](queryaffectedbatch_mean.png "Mean latency for POST /v1/querybatch dropped from ~1.8s (dashed) to ~0.6s (solid).")

On average, the `GET /v1/vulns/{id}` endpoint is 5x faster, `POST /v1/query` is 2.5x faster, and `POST /v1/querybatch` is 3x faster.

In terms of percentiles, you can see our P50 (blue), P90 (green), and P95 (purple) latencies below:
![Line graph of GET /v1/vulns/{id} latency percentiles, comparing the higher 'before' state (dashed lines) to the significantly lower 'after' state (solid lines).](getvulnbyid_percentiles.png "P50/P90/P95 latencies for GET /v1/vulns/{id} before (dashed) and after (solid), showing a significant drop.")
![Line graph of POST /v1/query latency percentiles, comparing the higher 'before' state (dashed lines) to the significantly lower 'after' state (solid lines).](queryaffected_percentiles.png "P50/P90/P95 latencies for POST /v1/query before (dashed) and after (solid), showing a significant drop.")
![Line graph of POST /v1/querybatch latency percentiles, comparing the higher 'before' state (dashed lines) to the significantly lower 'after' state (solid lines).](queryaffectedbatch_percentiles.png "P50/P90/P95 latencies for POST /v1/querybatch before (dashed) and after (solid), showing a significant drop.")

Notably, this takes our batch query 95th percentile from ~10 seconds to ~3 seconds, which should significantly improve performance when performing dependency scanning.

## Updated API SLOs

With this new performance profile, we've adjusted our [Service Level Objectives (SLOs)](https://google.github.io/osv.dev/faq/#what-are-osvdevs-service-level-objectives-slos:~:text=(e.g.%20big%20OSV%20Linux%20queries).-,What%20are%20OSV.dev%E2%80%99s%20service%20level%20objectives%20(SLOs)%3F,-OSV.dev%20strives) to better reflect the characteristics of the API, and are now tracking each endpoint separately. Our new SLOs are as follows:
- `GET /v1/vulns/{id}`: P50 ≤ 100ms, P90 ≤ 200ms, P95 ≤ 500ms
- `POST /v1/query`: P50 ≤ 300ms, P90 ≤ 500ms, P95 ≤ 1s
- `POST /v1/querybatch`: P50 ≤ 500ms, P90 ≤ 4s, P95 ≤ 6s

## Further Plans

With these API latency improvements in place, our next focus is on speeding up the ingestion and export pipelines. This will improve how quickly new vulnerability information is made available to OSV.dev users.
