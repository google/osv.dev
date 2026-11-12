import "./linter.scss";
import "@github/clipboard-copy-element";

const SINCE_LABELS = {
  "": "Any time",
  "24h": "New in last 24h",
  "7d": "New in last 7 days",
  "30d": "New in last 30 days",
  "90d": "New in last 90 days",
};

const LEGACY_FINDING_TO_CODES = {
  INVALID_JSON: ["SCH:001"],
  INVALID_RECORD: ["REC:001"],
  INVALID_ALIASES: ["REC:002"],
  INVALID_UPSTREAM: ["REC:003"],
  INVALID_RELATED: ["REC:004"],
  INVALID_RANGE: ["RNG:001", "RNG:002"],
  INVALID_PACKAGE: ["PKG:001"],
  INVALID_VERSION: ["PKG:002"],
  INVALID_PURL: ["PKG:003"],
  INVALID_COMMIT: ["COMMIT:001"],
  BAD_ALIASED_CVE: ["CVE:001"],
  DELETED: ["DEL:001"],
};

document.addEventListener("DOMContentLoaded", function () {
  const apiUrl = (document.body.dataset.apiUrl || "api.test.osv.dev").replace(/^https?:\/\//, "");
  let activeVulnData = {};
  let activeVulnValueMaps = {};
  let issuesPerPage = 25;
  let currentPage = 1;
  let totalIssues = 0;
  let sortField = "last_attempt";
  let sortDirection = "desc";
  let activeQueryController = null;
  let searchDebounceTimer = null;
  let timestampRetryTimer = null;
  let timestampRetryCount = 0;
  const maxTimestampRetries = 6;

  const globalLoader = document.getElementById("global-loader");
  const searchInput = document.getElementById("search-input");
  const tabBarContainer = document.querySelector(".tab-bar-container");
  const tabSwitch = document.getElementById("tab-switch");
  const tabsContent = document.getElementById("tabs-content");

  const homeDbFilter = document.getElementById("homedb-filter");
  const homeDbFilterSelected = document.getElementById("homedb-filter-selected");
  const homeDbFilterOptions = document.getElementById("homedb-filter-options");
  const homeDbSearchInput = document.getElementById("homedb-search-input");

  const findingsFilter = document.getElementById("findings-filter");
  const findingsFilterSelected = document.getElementById("findings-filter-selected");
  const findingsFilterOptions = document.getElementById("findings-filter-options");
  const findingsSearchInput = document.getElementById("findings-search-input");

  const sinceFilter = document.getElementById("since-filter");
  const sinceFilterSelected = document.getElementById("since-filter-selected");
  const sinceFilterOptions = document.getElementById("since-filter-options");

  const activeChipsEl = document.getElementById("active-filter-chips");
  const syncStatusEl = document.getElementById("timestamps-sync-status");
  const resultsSummaryEl = document.getElementById("results-summary");
  const pageSizeSelect = document.getElementById("page-size-select");

  let selectedSources = new Set();
  let sourceMode = "include";
  let selectedCodes = new Set();
  let selectedCategories = new Set();
  let ruleMode = "include";
  let selectedSince = "";
  let latestFacets = {};

  function splitCSV(val) {
    return val ? val.split(",").map((s) => s.trim()).filter(Boolean) : [];
  }

  function applyFiltersFromURL() {
    const params = new URLSearchParams(window.location.search);
    selectedSources = new Set(splitCSV(params.get("homedb") || params.get("source")));
    sourceMode = params.get("source_mode") === "exclude" ? "exclude" : "include";

    selectedCodes = new Set();
    splitCSV(params.get("code")).forEach((c) => selectedCodes.add(c.toUpperCase()));
    splitCSV(params.get("finding")).forEach((f) => {
      const key = f.toUpperCase().replace(/^IMPORT_FINDING_TYPE_/, "");
      (LEGACY_FINDING_TO_CODES[key] || [key]).forEach((c) => selectedCodes.add(c));
    });
    selectedCategories = new Set(splitCSV(params.get("cat") || params.get("category")).map((c) => c.toUpperCase()));
    ruleMode = params.get("rule_mode") === "exclude" ? "exclude" : "include";
    selectedSince = params.get("since") || "";
    searchInput.value = params.get("q") || "";

    const sort = params.get("sort");
    if (["last_attempt", "first_seen", "bug_id", "finding_count"].includes(sort)) sortField = sort;
    if (params.get("order") === "asc") sortDirection = "asc";
    const page = parseInt(params.get("page") || "1", 10);
    if (page > 0) currentPage = page;
    const ps = parseInt(params.get("page_size") || "25", 10);
    if ([15, 25, 50, 100].includes(ps)) issuesPerPage = ps;
    pageSizeSelect.value = String(issuesPerPage);
  }

  function updateURL(replace = true) {
    const params = new URLSearchParams();
    if (selectedSources.size > 0) {
      params.set("homedb", Array.from(selectedSources).join(","));
      if (sourceMode === "exclude") params.set("source_mode", "exclude");
    }
    if (selectedCodes.size > 0) params.set("code", Array.from(selectedCodes).join(","));
    if (selectedCategories.size > 0) params.set("cat", Array.from(selectedCategories).join(","));
    if ((selectedCodes.size > 0 || selectedCategories.size > 0) && ruleMode === "exclude") {
      params.set("rule_mode", "exclude");
    }
    if (selectedSince) params.set("since", selectedSince);
    if (searchInput.value.trim()) params.set("q", searchInput.value.trim());
    if (sortField !== "last_attempt") params.set("sort", sortField);
    if (sortDirection !== "desc") params.set("order", sortDirection);
    if (currentPage > 1) params.set("page", String(currentPage));
    if (issuesPerPage !== 25) params.set("page_size", String(issuesPerPage));

    const qs = params.toString();
    const newURL = qs ? `${window.location.pathname}?${qs}` : window.location.pathname;
    history[replace ? "replaceState" : "pushState"]({ path: newURL }, "", newURL);
  }

  applyFiltersFromURL();

  async function fetchIssues(isTimestampRetry = false) {
    clearTimeout(timestampRetryTimer);
    if (!isTimestampRetry) {
      timestampRetryCount = 0;
    }
    if (activeQueryController) activeQueryController.abort();
    const controller = new AbortController();
    activeQueryController = controller;
    globalLoader.classList.add("visible");
    updateURL(true);

    const params = new URLSearchParams();
    if (selectedSources.size > 0) {
      params.set("source", Array.from(selectedSources).join(","));
      params.set("source_mode", sourceMode);
    }
    if (selectedCodes.size > 0) params.set("code", Array.from(selectedCodes).join(","));
    if (selectedCategories.size > 0) params.set("cat", Array.from(selectedCategories).join(","));
    if (selectedCodes.size > 0 || selectedCategories.size > 0) params.set("rule_mode", ruleMode);
    if (selectedSince) params.set("since", selectedSince);
    if (searchInput.value.trim()) params.set("q", searchInput.value.trim());
    params.set("sort", sortField);
    params.set("order", sortDirection);
    params.set("page", String(currentPage));
    params.set("page_size", String(issuesPerPage));

    try {
      const res = await fetch(`/linter-findings/query?${params.toString()}`, {
        signal: controller.signal,
      });
      if (!res.ok) {
        throw new Error(`Request failed (${res.status})`);
      }
      const data = await res.json();
      if (controller.signal.aborted) return;

      totalIssues = data.total || 0;
      currentPage = data.page || 1;
      latestFacets = data.facets || {};

      if (data.timestamps_ready) {
        syncStatusEl.hidden = true;
        timestampRetryCount = 0;
      } else {
        syncStatusEl.hidden = false;
        if (timestampRetryCount < maxTimestampRetries) {
          const delayMs = Math.min(1500 * Math.pow(2, timestampRetryCount), 15000);
          timestampRetryCount++;
          syncStatusEl.textContent = "Syncing First Seen timestamps...";
          timestampRetryTimer = setTimeout(() => fetchIssues(true), delayMs);
        } else {
          syncStatusEl.textContent = "First Seen timestamps still syncing (reload later)";
        }
      }

      updateDynamicFilterCounts(latestFacets);
      renderActiveChips();
      displayIssues(data.issues || []);
    } catch (err) {
      if (err.name === "AbortError") return;
      console.error("Failed loading linter findings:", err);
      const tableBody = document
        .getElementById("issues-table")
        .getElementsByTagName("tbody")[0];
      tableBody.innerHTML = '<tr><td colspan="5">Failed to load issues.</td></tr>';
      totalIssues = 0;
      resultsSummaryEl.textContent = "";
      setupPagination();
    } finally {
      if (activeQueryController === controller) {
        globalLoader.classList.remove("visible");
      }
    }
  }

  function syncModeButtons() {
    document.querySelectorAll(".mode-btn[data-filter='homedb']").forEach((b) => {
      b.classList.toggle("active", b.dataset.mode === sourceMode);
    });
    document.querySelectorAll(".mode-btn[data-filter='findings']").forEach((b) => {
      b.classList.toggle("active", b.dataset.mode === ruleMode);
    });
  }

  function syncSortHeaders() {
    document.querySelectorAll("#issues-table th[data-sort]").forEach((th) => {
      const icon = th.querySelector(".material-icons");
      if (!icon) return;
      icon.textContent = th.dataset.sort === sortField
        ? (sortDirection === "asc" ? "expand_less" : "expand_more")
        : "unfold_more";
    });
  }

  function processAndDisplayData() {
    syncModeButtons();
    syncSortHeaders();
    sinceFilterSelected.textContent = SINCE_LABELS[selectedSince] || selectedSince;
    fetchIssues();

    searchInput.addEventListener("input", () => {
      clearTimeout(searchDebounceTimer);
      searchDebounceTimer = setTimeout(() => {
        currentPage = 1;
        fetchIssues();
      }, 200);
    });

    document.querySelectorAll("#issues-table th[data-sort]").forEach((th) => {
      th.addEventListener("click", () => {
        const nextField = th.dataset.sort;
        if (sortField === nextField) {
          sortDirection = sortDirection === "asc" ? "desc" : "asc";
        } else {
          sortField = nextField;
          sortDirection = nextField === "bug_id" ? "asc" : "desc";
        }
        syncSortHeaders();
        currentPage = 1;
        fetchIssues();
      });
    });

    pageSizeSelect.addEventListener("change", () => {
      issuesPerPage = parseInt(pageSizeSelect.value, 10) || 25;
      currentPage = 1;
      fetchIssues();
    });

    tabBarContainer.addEventListener("click", handleTabClick);

    tabSwitch.addEventListener("wheel", (e) => {
      if (e.deltaY !== 0) {
        e.preventDefault();
        tabSwitch.scrollLeft += e.deltaY;
      }
    });

    tabSwitch.addEventListener("scroll", () => {
      tabBarContainer.classList.toggle("scrolled", tabSwitch.scrollLeft > 0);
    });

    homeDbFilter.addEventListener("click", (e) => {
      e.stopPropagation();
      toggleFilter("homedb", homeDbSearchInput);
    });
    findingsFilter.addEventListener("click", (e) => {
      e.stopPropagation();
      toggleFilter("findings", findingsSearchInput);
    });
    sinceFilter.addEventListener("click", (e) => {
      e.stopPropagation();
      toggleFilter("since");
    });

    homeDbSearchInput.addEventListener("input", () => updateDynamicFilterCounts(latestFacets));
    findingsSearchInput.addEventListener("input", () => updateDynamicFilterCounts(latestFacets));

    document.querySelectorAll(".mode-btn").forEach((btn) => {
      btn.addEventListener("click", () => {
        if (btn.dataset.filter === "homedb" && sourceMode !== btn.dataset.mode) {
          sourceMode = btn.dataset.mode;
          syncModeButtons();
          if (selectedSources.size > 0) {
            currentPage = 1;
            fetchIssues();
          }
        } else if (btn.dataset.filter === "findings" && ruleMode !== btn.dataset.mode) {
          ruleMode = btn.dataset.mode;
          syncModeButtons();
          if (selectedCodes.size > 0 || selectedCategories.size > 0) {
            currentPage = 1;
            fetchIssues();
          }
        }
      });
    });

    document.getElementById("homedb-clear-btn").addEventListener("click", () => {
      if (selectedSources.size > 0) {
        selectedSources.clear();
        currentPage = 1;
        fetchIssues();
      }
    });
    document.getElementById("findings-clear-btn").addEventListener("click", () => {
      if (selectedCodes.size > 0 || selectedCategories.size > 0) {
        selectedCodes.clear();
        selectedCategories.clear();
        currentPage = 1;
        fetchIssues();
      }
    });

    sinceFilterOptions.addEventListener("click", (e) => {
      const opt = e.target.closest(".filter-option");
      if (!opt) return;
      selectedSince = opt.dataset.value || "";
      sinceFilterSelected.textContent = opt.textContent;
      sinceFilterOptions.style.display = "none";
      currentPage = 1;
      fetchIssues();
    });
  }

  function appendCheckboxRow(container, labelText, count, checked, className, onChange) {
    const row = document.createElement("label");
    row.className = `check-option ${className}${count === 0 ? " zero-count" : ""}`;
    const left = document.createElement("span");
    left.className = "check-option-left";
    const cb = document.createElement("input");
    cb.type = "checkbox";
    cb.checked = checked;
    cb.addEventListener("change", () => onChange(cb.checked));
    left.appendChild(cb);
    left.appendChild(document.createTextNode(labelText));
    const badge = document.createElement("span");
    badge.textContent = count.toLocaleString();
    row.appendChild(left);
    row.appendChild(badge);
    container.appendChild(row);
  }

  function updateDynamicFilterCounts(facets) {
    const rulesTerm = findingsSearchInput.value.toLowerCase().trim();
    const categories = facets.categories || [];
    const rules = facets.rules || [];
    const totalForRules = facets.total_for_rules || 0;

    const prevRulesScroll = findingsFilterOptions.scrollTop;
    findingsFilterOptions.replaceChildren();
    categories.forEach((cat) => {
      const catRules = rules.filter((r) => r.category === cat.code);
      const catMatch = !rulesTerm || cat.code.toLowerCase().includes(rulesTerm) || cat.label.toLowerCase().includes(rulesTerm);
      const visibleRules = catMatch ? catRules : catRules.filter((r) =>
        r.code.toLowerCase().includes(rulesTerm) || r.label.toLowerCase().includes(rulesTerm)
      );
      if (!catMatch && visibleRules.length === 0) return;

      appendCheckboxRow(
        findingsFilterOptions,
        `${cat.code} — ${cat.label}`,
        cat.count,
        selectedCategories.has(cat.code),
        "is-category",
        (checked) => {
          if (checked) {
            selectedCategories.add(cat.code);
          } else {
            selectedCategories.delete(cat.code);
          }
          currentPage = 1;
          fetchIssues();
        }
      );
      visibleRules.forEach((r) => {
        appendCheckboxRow(
          findingsFilterOptions,
          `${r.code} (${r.label})`,
          r.count,
          selectedCodes.has(r.code),
          "is-child",
          (checked) => {
            if (checked) {
              selectedCodes.add(r.code);
            } else {
              selectedCodes.delete(r.code);
            }
            currentPage = 1;
            fetchIssues();
          }
        );
      });
    });
    findingsFilterOptions.scrollTop = prevRulesScroll;

    const ruleTokens = [...Array.from(selectedCategories).map((c) => `${c}:*`), ...Array.from(selectedCodes)];
    findingsFilter.classList.toggle("has-active-include", ruleTokens.length > 0 && ruleMode === "include");
    findingsFilter.classList.toggle("has-active-exclude", ruleTokens.length > 0 && ruleMode === "exclude");
    findingsFilterSelected.textContent = ruleTokens.length === 0
      ? `All (${totalForRules.toLocaleString()} issues)`
      : `${ruleMode === "exclude" ? "Excl: " : ""}${ruleTokens.join(", ")}`;

    const srcTerm = homeDbSearchInput.value.toLowerCase().trim();
    const sources = [...(facets.sources || [])].sort((a, b) => b.count - a.count || a.name.localeCompare(b.name));
    const totalForSources = facets.total_for_sources || 0;

    const prevSourcesScroll = homeDbFilterOptions.scrollTop;
    homeDbFilterOptions.replaceChildren();
    sources.forEach((src) => {
      if (src.count === 0 && !selectedSources.has(src.name)) return;
      if (srcTerm && !src.name.toLowerCase().includes(srcTerm)) return;
      appendCheckboxRow(homeDbFilterOptions, src.name, src.count, selectedSources.has(src.name), "", (checked) => {
        if (checked) {
          selectedSources.add(src.name);
        } else {
          selectedSources.delete(src.name);
        }
        currentPage = 1;
        fetchIssues();
      });
    });
    homeDbFilterOptions.scrollTop = prevSourcesScroll;

    homeDbFilter.classList.toggle("has-active-include", selectedSources.size > 0 && sourceMode === "include");
    homeDbFilter.classList.toggle("has-active-exclude", selectedSources.size > 0 && sourceMode === "exclude");
    homeDbFilterSelected.textContent = selectedSources.size === 0
      ? `All (${totalForSources.toLocaleString()} issues)`
      : `${sourceMode === "exclude" ? "Excl: " : ""}${Array.from(selectedSources).join(", ")}`;
  }

  function renderActiveChips() {
    activeChipsEl.replaceChildren();
    const chips = [];
    selectedSources.forEach((s) => chips.push({
      label: `${sourceMode === "exclude" ? "DB ≠ " : "DB: "}${s}`,
      exclude: sourceMode === "exclude",
      remove: () => {
        selectedSources.delete(s);
        currentPage = 1;
        fetchIssues();
      },
    }));
    selectedCategories.forEach((c) => chips.push({
      label: `${ruleMode === "exclude" ? "Cat ≠ " : "Cat: "}${c}`,
      exclude: ruleMode === "exclude",
      remove: () => {
        selectedCategories.delete(c);
        currentPage = 1;
        fetchIssues();
      },
    }));
    selectedCodes.forEach((c) => chips.push({
      label: `${ruleMode === "exclude" ? "Rule ≠ " : "Rule: "}${c}`,
      exclude: ruleMode === "exclude",
      remove: () => {
        selectedCodes.delete(c);
        currentPage = 1;
        fetchIssues();
      },
    }));
    if (selectedSince) {
      chips.push({
        label: `First seen: ${SINCE_LABELS[selectedSince] || selectedSince}`,
        remove: () => {
          selectedSince = "";
          sinceFilterSelected.textContent = SINCE_LABELS[""];
          currentPage = 1;
          fetchIssues();
        },
      });
    }
    if (searchInput.value.trim()) {
      chips.push({
        label: `Search: "${searchInput.value.trim()}"`,
        remove: () => {
          searchInput.value = "";
          currentPage = 1;
          fetchIssues();
        },
      });
    }

    chips.forEach((c) => {
      const chip = document.createElement("span");
      chip.className = `filter-chip${c.exclude ? " exclude-chip" : ""}`;
      chip.textContent = c.label;
      const btn = document.createElement("button");
      btn.type = "button";
      btn.innerHTML = '<i class="material-icons">close</i>';
      btn.addEventListener("click", c.remove);
      chip.appendChild(btn);
      activeChipsEl.appendChild(chip);
    });

    if (chips.length > 1) {
      const clearAll = document.createElement("button");
      clearAll.type = "button";
      clearAll.className = "clear-all-chips-btn";
      clearAll.textContent = "Clear all";
      clearAll.addEventListener("click", () => {
        selectedSources.clear();
        selectedCategories.clear();
        selectedCodes.clear();
        sourceMode = "include";
        ruleMode = "include";
        selectedSince = "";
        searchInput.value = "";
        sinceFilterSelected.textContent = SINCE_LABELS[""];
        syncModeButtons();
        currentPage = 1;
        fetchIssues();
      });
      activeChipsEl.appendChild(clearAll);
    }
  }

  function displayIssues(paginatedIssues) {
    const tableBody = document
      .getElementById("issues-table")
      .getElementsByTagName("tbody")[0];
    tableBody.innerHTML = "";
    resultsSummaryEl.textContent = totalIssues > 0
      ? `${totalIssues.toLocaleString()} matching issues`
      : "0 issues";

    if (paginatedIssues.length === 0) {
      tableBody.innerHTML = '<tr><td colspan="5">No issues found.</td></tr>';
    } else {
      paginatedIssues.forEach((issue) => {
        const row = tableBody.insertRow();
        row.classList.add("clickable");
        row.addEventListener("click", () => {
          openCombinedView(issue.bug_id, issue.details || []);
        });

        const cell1 = row.insertCell();
        const cell2 = row.insertCell();
        const cell3 = row.insertCell();
        const cell4 = row.insertCell();
        const cell5 = row.insertCell();

        const bugLink = document.createElement("a");
        bugLink.href = `https://${apiUrl}/v1/vulns/${encodeURIComponent(issue.bug_id)}`;
        bugLink.textContent = issue.bug_id;
        bugLink.addEventListener("click", (e) => {
          e.stopPropagation();
          openCombinedView(issue.bug_id, issue.details || []);
          e.preventDefault();
        });
        cell1.appendChild(bugLink);

        cell2.textContent = issue.source || "—";

        const findingsContainer = document.createElement("div");
        (issue.codes || []).forEach((code) => {
          const findingSpan = document.createElement("span");
          findingSpan.textContent = code;
          findingSpan.className = "finding-tag";
          findingsContainer.appendChild(findingSpan);
        });
        cell3.appendChild(findingsContainer);

        cell4.textContent = issue.first_seen
          ? new Date(issue.first_seen).toLocaleDateString()
          : "—";
        cell5.textContent = issue.last_attempt
          ? new Date(issue.last_attempt).toLocaleString()
          : "—";
      });
    }
    setupPagination();
  }

  function setupPagination() {
    const paginationControls = document.getElementById("pagination-controls");
    paginationControls.innerHTML = "";
    const pageCount = Math.ceil(totalIssues / issuesPerPage);

    if (pageCount <= 1) return;

    const prevButton = document.createElement("button");
    prevButton.textContent = "Previous";
    prevButton.disabled = currentPage === 1;
    prevButton.addEventListener("click", () => {
      if (currentPage > 1) {
        currentPage--;
        fetchIssues();
      }
    });
    paginationControls.appendChild(prevButton);

    const pageInfo = document.createElement("span");
    pageInfo.textContent = ` Page ${currentPage} of ${pageCount} `;
    pageInfo.style.margin = "0 10px";
    paginationControls.appendChild(pageInfo);

    const nextButton = document.createElement("button");
    nextButton.textContent = "Next";
    nextButton.disabled = currentPage === pageCount;
    nextButton.addEventListener("click", () => {
      if (currentPage < pageCount) {
        currentPage++;
        fetchIssues();
      }
    });
    paginationControls.appendChild(nextButton);
  }

  /**
   * Sanitizes a vulnerability ID string by stripping special characters for safe DOM element ID usage.
   * @param {string} bugId - Raw vulnerability identifier.
   * @returns {string} Sanitized ID string.
   */
  function sanitiseBugId(bugId) {
    // Keep only alphanumeric characters, hyphens, and colons
    return bugId.replace(/[^a-zA-Z0-9-:]/g, "");
  }

  /**
   * Opens a detailed tab view split into Vulnerability JSON and Linter Findings columns.
   * Fetches full vulnerability record JSON from the same-origin endpoint and renders the interactive JSON tree.
   * @param {string} bugId - Vulnerability identifier.
   * @param {Array<Object>} [details=[]] - Inline linter finding objects for the vulnerability.
   */
  function openCombinedView(bugId, details = []) {
    const safeBugId = sanitiseBugId(bugId);

    const tabId = `details-${safeBugId}`;
    const existingTab = tabBarContainer.querySelector(`[data-tab="${tabId}"]`);
    if (existingTab) {
      setActiveTab(tabId);
      return;
    }

    const tabButton = document.createElement("div");
    tabButton.className = "tab-switch-button";
    tabButton.dataset.tab = tabId;

    const titleSpan = document.createElement("span");
    titleSpan.className = "tab-title";
    titleSpan.textContent = bugId;
    tabButton.appendChild(titleSpan);

    const closeButton = document.createElement("i");
    closeButton.className = "material-icons close-tab";
    closeButton.textContent = "close";
    closeButton.dataset.tabClose = tabId;
    tabButton.appendChild(closeButton);

    tabSwitch.appendChild(tabButton);

    const vulnJsonId = `vuln-json-${safeBugId}`;
    const findingsJsonId = `findings-json-${safeBugId}`;
    const copyButtonId = `copy-json-${safeBugId}`;

    const tabContent = document.createElement("div");
    tabContent.className = "tab-content";
    tabContent.id = tabId;

    tabContent.innerHTML = `
      <div class="details-grid">
          <div class="details-column">
              <div class="details-header">
                  <h2>Vulnerability Data</h2>
                  <clipboard-copy id="${copyButtonId}" class="copy-button" title="Copy raw JSON">
                      <i class="material-icons">content_copy</i>
                  </clipboard-copy>
              </div>
              <div id="${vulnJsonId}" class="json-container">Loading...</div>
          </div>
          <div class="details-column">
              <div class="details-header">
                  <h2>Linter Findings</h2>
              </div>
              <div id="${findingsJsonId}" class="json-pre">Loading...</div>
          </div>
      </div>
                `;

    tabsContent.appendChild(tabContent);
    setActiveTab(tabId);

    const encodedId = encodeURIComponent(bugId);
    fetch(`/linter-findings/vuln/${encodedId}`)
      .then((res) =>
        res.ok ? res.json() : { error: `Failed to load: ${res.status}` }
      )
      .then((data) => {
        const container = document.getElementById(vulnJsonId);
        container.textContent = ''; // Clear "Loading..."
        if (data.error) {
          container.textContent = data.error;
          return;
        }
        activeVulnData[bugId] = data;

        const copyButton = document.getElementById(copyButtonId);
        if (copyButton) {
          const jsonStr = JSON.stringify(data, null, 2);
          copyButton.value = jsonStr;
          copyButton.setAttribute('value', jsonStr);
          copyButton.addEventListener('clipboard-copy', () => {
            const icon = copyButton.querySelector('.material-icons');
            if (icon) icon.textContent = 'check';
            setTimeout(() => {
              if (icon) icon.textContent = 'content_copy';
            }, 2000);
          });
        }

        const valueMap = {};
        activeVulnValueMaps[bugId] = valueMap;
        
        container.appendChild(renderCustomJSON(data, '', true, valueMap));

        // Use Event Delegation on the container for collapsible JSON nodes
        container.addEventListener('click', (e) => {
          const toggle = e.target.closest('.json-toggle');
          if (!toggle) return;
          e.stopPropagation();
          const isOpen = toggle.classList.toggle('open');
          setToggleState(toggle, isOpen);
          const children = toggle.nextElementSibling;
          if (children && children.classList.contains('json-children')) {
            children.style.display = isOpen ? 'block' : 'none';
          }
        });
      })
      .catch((err) => {
        document.getElementById(
          vulnJsonId
        ).textContent = `Error: ${err.message}`;
      });

    const findingsEl = document.getElementById(findingsJsonId);
    if (findingsEl) {
      if (details.length > 0) {
        findingsEl.textContent = "";
        findingsEl.appendChild(formatFindings(details, bugId));
      } else {
        findingsEl.textContent =
          "No linter findings available for this vulnerability.";
      }
    }
  }

  /**
   * Updates the visual open/collapsed state and label text of a JSON toggle element.
   * @param {HTMLElement} toggle - The toggle span element.
   * @param {boolean} isOpen - Whether the section is expanded.
   */
  function setToggleState(toggle, isOpen) {
    toggle.classList.toggle('open', isOpen);
    const isArray = toggle.dataset.isObject !== 'true';
    toggle.textContent = isOpen 
      ? (isArray ? '▼ [' : '▼ {') 
      : (isArray ? '▶ [...]' : '▶ {...}');
  }

  /**
   * Generates an HTML table displaying linter findings for a given vulnerability.
   * @param {Array<Object>} details - List of linter finding objects.
   * @param {string} bugId - The vulnerability identifier.
   * @returns {HTMLTableElement} The constructed findings table element.
   */
  function formatFindings(details, bugId) {
    const table = document.createElement('table');
    table.className = 'findings-table';

    const thead = table.createTHead();
    const headerRow = thead.insertRow();
    ['Code', 'Message', ''].forEach(headerText => {
      const th = document.createElement('th');
      th.textContent = headerText;
      headerRow.appendChild(th);
    });

    const tbody = table.createTBody();
    details.forEach((finding) => {
      const row = tbody.insertRow();
      row.className = 'clickable-finding-row';
      row.insertCell().textContent = finding.Code || '';
      row.insertCell().textContent = finding.Message || '';
      
      const actionCell = row.insertCell();
      actionCell.className = 'action-cell';
      actionCell.innerHTML = '<i class="material-icons">search</i>';

      row.addEventListener('click', () => {
        highlightFinding(bugId, finding);
      });
    });

    return table;
  }

  /**
   * Recursively searches an object for a target value and returns all dot-separated JSON paths leading to it.
   * @param {*} obj - The object or value to inspect.
   * @param {*} value - The target value to locate.
   * @param {string[]} [currentPath=[]] - Accumulated path segments.
   * @param {string[]} [results=[]] - Accumulated path string results.
   * @returns {string[]} Found path strings.
   */
  function findPathsForValue(obj, value, currentPath = [], results = []) {
    if (obj === value) {
      results.push(currentPath.join('.'));
      return results;
    }
    if (typeof obj === 'object' && obj !== null) {
      for (const key in obj) {
        findPathsForValue(obj[key], value, [...currentPath, key], results);
      }
    }
    return results;
  }

  /**
   * Compares two range objects to check if their type, repo, and events match.
   * @param {Object} r1 - First range object.
   * @param {Object} r2 - Second range object.
   * @returns {boolean} True if ranges match.
   */
  function isSameRange(r1, r2) {
    if (r1.type !== r2.type) return false;
    if (r1.repo !== r2.repo) return false;
    if (!r1.events || !r2.events) return r1.events === r2.events;
    if (r1.events.length !== r2.events.length) return false;
    return JSON.stringify(r1.events) === JSON.stringify(r2.events);
  }

  /**
   * Finds the path to a specific affected range within the vulnerability record.
   * @param {Object} vulnData - The vulnerability protocol buffer JSON data.
   * @param {Object} targetRange - Range object to find.
   * @returns {string|null} Path string if found, otherwise null.
   */
  function findRangePath(vulnData, targetRange) {
    if (!vulnData || !vulnData.affected) return null;
    for (let i = 0; i < vulnData.affected.length; i++) {
      const affected = vulnData.affected[i];
      if (!affected.ranges) continue;
      for (let j = 0; j < affected.ranges.length; j++) {
        if (isSameRange(affected.ranges[j], targetRange)) {
          return `affected.${i}.ranges.${j}`;
        }
      }
    }
    return null;
  }

  /**
   * Extracts JSON paths from a linter finding message.
   * Handles schema errors (SCH:xxx), quote/value matches (RNG:002), range types, and top-level properties (REC:xxx).
   * @param {Object} finding - Finding record with Code and Message properties.
   * @param {string} bugId - Vulnerability ID.
   * @returns {string[]} Array of target JSON path strings.
   */
  function extractPathsFromFinding(finding, bugId) {
    const paths = [];
    if (!finding || !finding.Message) return paths;

    const vulnData = activeVulnData[bugId];
    const valueMap = activeVulnValueMaps[bugId];

    // 1. Check for schema paths (SCH:xxx)
    const schemaPathRegex = /(?:^|\s)-\s*([a-zA-Z0-9_\.]+):/g;
    let match;
    while ((match = schemaPathRegex.exec(finding.Message)) !== null) {
      paths.push(match[1]);
    }

    // 2. Check for overlapping event values (RNG:002) or anything in quotes using O(1) indexed valueMap
    const quoteRegex = /"([^"]+)"/g;
    let quoteMatch;
    while ((quoteMatch = quoteRegex.exec(finding.Message)) !== null) {
      const value = quoteMatch[1];
      if (!value.startsWith('{')) {
        if (valueMap && valueMap[value]) {
          paths.push(...valueMap[value]);
        } else if (vulnData) {
          const valuePaths = findPathsForValue(vulnData, value);
          paths.push(...valuePaths);
        }
      }
    }

    // 3. Check for unexpected range type (RNG:002 case 2)
    const rngTypeRegex = /unexpected range type "[^"]+" for (\{[\s\S]*\})/;
    const rngTypeMatch = rngTypeRegex.exec(finding.Message);
    if (rngTypeMatch) {
      try {
        const targetRange = JSON.parse(rngTypeMatch[1]);
        const path = findRangePath(vulnData, targetRange);
        if (path) {
          paths.push(path);
        }
      } catch (e) {
        console.error("Failed to parse range JSON from finding", e);
      }
    }

    // 4. Check for invalid top-level properties (REC:xxx)
    const invalidPropRegex = /Invalid ([a-zA-Z0-9_]+):/i;
    const invalidPropMatch = invalidPropRegex.exec(finding.Message);
    if (invalidPropMatch) {
      paths.push(invalidPropMatch[1].toLowerCase());
    }

    return paths;
  }

  /**
   * Highlights target finding elements in the interactive JSON tree and auto-expands parent nodes.
   * @param {string} bugId - Vulnerability ID.
   * @param {Object} finding - Linter finding object to highlight.
   */
  function highlightFinding(bugId, finding) {
    const safeBugId = sanitiseBugId(bugId);
    const vulnJsonId = `vuln-json-${safeBugId}`;
    const container = document.getElementById(vulnJsonId);
    if (!container) return;

    // Clear previous highlights
    container.querySelectorAll('.json-highlighted').forEach(el => {
      el.classList.remove('json-highlighted');
    });

    const paths = extractPathsFromFinding(finding, bugId);
    let firstHighlighted = null;

    paths.forEach(path => {
      const row = container.querySelector(`[data-json-path="${path}"]`);
      if (row) {
        row.classList.add('json-highlighted');
        
        // Ensure all parent elements are expanded
        let parent = row.parentElement;
        while (parent && parent !== container) {
          if (parent.classList.contains('json-children')) {
            parent.style.display = 'block';
            const toggle = parent.previousElementSibling;
            if (toggle?.classList.contains('json-toggle')) {
              setToggleState(toggle, true);
            }
          }
          parent = parent.parentElement;
        }

        // Expand the highlighted row itself if it is collapsed
        const myChildren = row.querySelector(':scope > .custom-json-node > .json-children');
        if (myChildren) {
          myChildren.style.display = 'block';
          const myToggle = row.querySelector(':scope > .custom-json-node > .json-toggle');
          if (myToggle) {
            setToggleState(myToggle, true);
          }
        }

        if (!firstHighlighted) {
          firstHighlighted = row;
        }
      }
    });

    if (firstHighlighted) {
      firstHighlighted.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }
  }

  /**
   * Recursively builds an interactive HTML DOM tree for rendering JSON structures with data-json-path attributes.
   * 
   * @param {*} data - The primitive or object value to render.
   * @param {string} [path=''] - The dot-separated JSON path leading to this node.
   * @param {boolean} [isRoot=false] - Whether this node is the root container of the JSON tree.
   * @param {Object<string, string[]>} [valueMap=null] - Optional lookup map populated with value -> path[] for O(1) searches.
   * @returns {HTMLElement} The root div.custom-json-node container element.
   */
  function renderCustomJSON(data, path = '', isRoot = false, valueMap = null) {
    const container = document.createElement('div');
    container.className = 'custom-json-node';
    if (path !== '') container.dataset.jsonPath = path;

    if (data === null || typeof data !== 'object') {
      if (valueMap && path && (typeof data === 'string' || typeof data === 'number')) {
        const strVal = String(data);
        if (!valueMap[strVal]) valueMap[strVal] = [];
        valueMap[strVal].push(path);
      }
      const span = document.createElement('span');
      const type = data === null ? 'null' : typeof data;
      span.className = `json-value-${type}`;
      span.textContent = type === 'string' ? `"${data}"` : String(data);
      container.appendChild(span);
      return container;
    }

    const isArray = Array.isArray(data);
    const keys = Object.keys(data);
    const openChar = isArray ? '[' : '{';
    const closeChar = isArray ? ']' : '}';

    if (keys.length === 0) {
      const span = document.createElement('span');
      span.className = 'json-bracket';
      span.textContent = `${openChar}${closeChar}`;
      container.appendChild(span);
      return container;
    }

    const toggle = document.createElement('span');
    toggle.className = 'json-toggle open';
    toggle.dataset.isObject = (!isArray).toString();
    toggle.textContent = `▼ ${openChar}`;

    const children = document.createElement('div');
    children.className = 'json-children';

    keys.forEach(key => {
      const val = data[key];
      const childPath = path ? `${path}.${key}` : `${key}`;
      const row = document.createElement('div');
      row.className = 'json-row';
      row.dataset.jsonPath = childPath;

      const keySpan = document.createElement('span');
      keySpan.className = isArray ? 'json-key array-index' : 'json-key';
      keySpan.textContent = isArray ? `${key}:` : `"${key}": `;
      row.appendChild(keySpan);

      row.appendChild(renderCustomJSON(val, childPath, false, valueMap));
      children.appendChild(row);
    });

    if (isRoot) {
      container.appendChild(document.createTextNode(openChar));
    } else {
      container.appendChild(toggle);
    }
    container.appendChild(children);

    const closeSpan = document.createElement('span');
    closeSpan.className = 'json-bracket';
    closeSpan.textContent = closeChar;
    container.appendChild(closeSpan);

    return container;
  }

  function handleTabClick(e) {
    const tabButton = e.target.closest(".tab-switch-button");
    if (tabButton) {
      if (e.target.classList.contains("close-tab")) {
        e.stopPropagation();
        closeTab(e.target.dataset.tabClose);
      } else {
        setActiveTab(tabButton.dataset.tab);
      }
    }
  }

  function setActiveTab(tabId) {
    // Buttons
    Array.from(tabBarContainer.querySelectorAll(".tab-switch-button")).forEach(
      (btn) => {
        btn.classList.toggle("active", btn.dataset.tab === tabId);
      }
    );
    // Content
    Array.from(tabsContent.children).forEach((content) => {
      content.classList.toggle("active", content.id === tabId);
    });
  }

  function closeTab(tabId) {
    const tabButton = tabBarContainer.querySelector(`[data-tab="${tabId}"]`);
    const tabContent = document.getElementById(tabId);

    if (tabButton) tabButton.remove();
    if (tabContent) tabContent.remove();

    // Activate the main tab if the closed one was active
    if (tabButton && tabButton.classList.contains("active")) {
      setActiveTab("linter-report");
    }
  }

  function toggleFilter(filterName, focusEl = null) {
    const panelId = filterName === "since" ? "since-filter-options" : `${filterName}-filter-panel`;
    const options = document.getElementById(panelId);
    const isVisible = options.style.display === "block";

    // Hide all filter options first
    document
      .querySelectorAll(".filter-option-container")
      .forEach((el) => (el.style.display = "none"));

    if (!isVisible) {
      options.style.display = "block";
      if (focusEl) setTimeout(() => focusEl.focus(), 0);
    }
  }

  document.addEventListener("click", function (e) {
    if (!e.target.closest(".filter-container")) {
      document
        .querySelectorAll(".filter-option-container")
        .forEach((el) => (el.style.display = "none"));
    }
  });

  processAndDisplayData();
});
