import "./linter.scss";

document.addEventListener("DOMContentLoaded", function () {
  let allIssues = [];
  let issuesByHomeDb = {};
  let filteredIssues = [];
  let findingDetails = {};
  const issuesPerPage = 15;
  let currentPage = 1;
  let sortDirection = "desc";
  let dataLoadingComplete = false;

  const globalLoader = document.getElementById("global-loader");
  const searchInput = document.getElementById("search-input");
  const modifiedHeader = document.getElementById("modified-header");
  const tabBarContainer = document.querySelector(".tab-bar-container");
  const tabSwitch = document.getElementById("tab-switch");
  const tabsContent = document.getElementById("tabs-content");

  const homeDbFilter = document.getElementById("homedb-filter");
  const homeDbFilterSelected = document.getElementById(
    "homedb-filter-selected"
  );
  const homeDbFilterOptions = document.getElementById(
    "homedb-filter-options"
  );

  const findingsFilter = document.getElementById("findings-filter");
  const findingsFilterSelected = document.getElementById(
    "findings-filter-selected"
  );
  const findingsFilterOptions = document.getElementById(
    "findings-filter-options"
  );

  let selectedHomeDb = "";
  let selectedFinding = "";
  let urlHomeDbApplied = false;

  function applyFiltersFromURL() {
    const params = new URLSearchParams(window.location.search);
    const homeDb = params.get("homedb");
    if (homeDb) {
      selectedHomeDb = homeDb;
    }
  }

  function updateURL(homeDb, replace = false) {
    const params = new URLSearchParams(window.location.search);
    if (homeDb) {
      params.set("homedb", homeDb);
    } else {
      params.delete("homedb");
    }
    const newURL = `${
      window.location.pathname
    }?${params.toString()}`.replace(/\?$/, "");

    if (replace) {
      history.replaceState({ path: newURL }, "", newURL);
    } else {
      history.pushState({ path: newURL }, "", newURL);
    }
  }

  applyFiltersFromURL();

  async function loadData() {
    globalLoader.classList.add("visible");

    // Get source names from github source_test.yaml file
    const response = await fetch(
      "https://raw.githubusercontent.com/google/osv.dev/master/source_test.yaml"
    );
    const yamlText = await response.text();
    const sources = jsyaml.load(yamlText);
    const sourceNames = sources.map((s) => s.name);

    // Check if the home database from the URL is not in the source yaml list.
    // If the queried home database is not in the source list, remove the invalid parameter from the URL.
    if (selectedHomeDb && !sourceNames.includes(selectedHomeDb)) {
      selectedHomeDb = "";
      urlHomeDbApplied = true; // Prevent further checks
      updateURL("", true);
    }

    processAndDisplayData();

    const allPromises = [];

    // Get the detailed linter results from GCS bucket
    const linterPromise = (async () => {
      const linterPromises = sourceNames.map((sourceName) => {
        const url = `https://storage.googleapis.com/osv-test-public-import-logs/linter-result/${sourceName}/result.json`;
        return fetch(url)
          .then((res) => (res.ok ? res.json() : {}))
          .catch(() => ({}));
      });
      const linterResults = await Promise.all(linterPromises);
      linterResults.forEach((data) => {
        for (const path in data) {
          const bugId = path.split("/").pop().replace(".json", "");
          if (!findingDetails[bugId]) findingDetails[bugId] = [];
          findingDetails[bugId].push(...data[path]);
        }
      });
    })();
    allPromises.push(linterPromise);

    // Get the import finding code from the API
    const issuePromises = sourceNames.map((sourceName) => {
      const url = `https://api.test.osv.dev/v1experimental/importfindings/${sourceName}`;
      return fetch(url)
        .then((res) => (res.ok ? res.json() : { invalid_records: [] }))
        .then((data) => {
          const records = data.invalid_records || [];
          allIssues.push(...records);
          records.forEach((issue) => {
            if (!issuesByHomeDb[issue.source]) {
              issuesByHomeDb[issue.source] = [];
            }
            issuesByHomeDb[issue.source].push(issue);
          });

          if (selectedHomeDb && !urlHomeDbApplied && issuesByHomeDb[selectedHomeDb]) {
            urlHomeDbApplied = true;
          }

          applyFilters();
        })
        .catch((error) =>
          console.error("Error loading data from " + url, error)
        );
    });
    allPromises.push(...issuePromises);

    // Wait for all data fetching to complete
    Promise.allSettled(allPromises).then(() => {
      dataLoadingComplete = true;
      globalLoader.classList.remove("visible");
      if (selectedHomeDb && !urlHomeDbApplied) {
        selectedHomeDb = "";
        updateURL("", true);
      }
      applyFilters(); // Final render
    });
  }

  function processAndDisplayData() {
    applyFilters();

    searchInput.addEventListener("input", applyFilters);
    modifiedHeader.addEventListener("click", () => {
      sortDirection = sortDirection === "asc" ? "desc" : "asc";
      const icon = modifiedHeader.querySelector(".material-icons");
      icon.textContent =
        sortDirection === "asc" ? "expand_less" : "expand_more";
      applyFilters();
    });
    tabBarContainer.addEventListener("click", handleTabClick);

    tabSwitch.addEventListener("wheel", (e) => {
      if (e.deltaY !== 0) {
        e.preventDefault();
        tabSwitch.scrollLeft += e.deltaY;
      }
    });

    tabSwitch.addEventListener("scroll", () => {
      if (tabSwitch.scrollLeft > 0) {
        tabBarContainer.classList.add("scrolled");
      } else {
        tabBarContainer.classList.remove("scrolled");
      }
    });

    homeDbFilter.addEventListener("click", (e) => {
      e.stopPropagation();
      toggleFilter("homedb");
    });
    findingsFilter.addEventListener("click", (e) => {
      e.stopPropagation();
      toggleFilter("findings");
    });

    homeDbFilterOptions.addEventListener("click", (e) => {
      if (e.target.classList.contains("filter-option")) {
        const { value, count } = e.target.dataset;
        selectedHomeDb = value;
        homeDbFilterSelected.textContent = `${value} (${count} issues)`;
        urlHomeDbApplied = true;
        updateURL(selectedHomeDb);
        applyFilters();
      }
    });

    findingsFilterOptions.addEventListener("click", (e) => {
      if (e.target.classList.contains("filter-option")) {
        const { value, name, count } = e.target.dataset;
        selectedFinding = value;
        findingsFilterSelected.textContent = `${name} (${count} issues)`;
        applyFilters();
      }
    });
  }

  function applyFilters() {
    const searchTerm = searchInput.value.toLowerCase();

    filteredIssues = allIssues.filter((issue) => {
      const bugIdMatch = issue.bug_id.toLowerCase().includes(searchTerm);
      const homeDbMatch =
        !selectedHomeDb || issue.source === selectedHomeDb;
      const findingMatch =
        !selectedFinding || issue.findings.includes(selectedFinding);
      return bugIdMatch && homeDbMatch && findingMatch;
    });

    currentPage = 1;
    sortIssues();
    updateDynamicFilterCounts();
    displayIssues();
  }

  function updateDynamicFilterCounts() {
    const searchTerm = searchInput.value.toLowerCase();

    // Update Findings counts
    const issuesForFindingsCount = allIssues.filter(
      (issue) =>
        (!selectedHomeDb || issue.source === selectedHomeDb) &&
        issue.bug_id.toLowerCase().includes(searchTerm)
    );
    const findingsCount = issuesForFindingsCount.reduce((acc, issue) => {
      issue.findings.forEach((finding) => {
        acc[finding] = (acc[finding] || 0) + 1;
      });
      return acc;
    }, {});

    findingsFilterOptions.innerHTML = `<div class="filter-option" data-value="">All (${issuesForFindingsCount.length})</div>`;
    for (const [finding, count] of Object.entries(findingsCount).sort((a, b) =>
      a[0].localeCompare(b[0])
    )) {
      const name = finding.replace("IMPORT_FINDING_TYPE_", "");
      const option = document.createElement("div");
      option.className = "filter-option";
      option.dataset.value = finding;
      option.dataset.name = name;
      option.dataset.count = count;
      option.textContent = `${name} (${count})`;
      findingsFilterOptions.appendChild(option);
    }
    if (!selectedFinding) {
      findingsFilterSelected.textContent = `All (${issuesForFindingsCount.length} issues)`;
    }

    // Update Home Database counts
    const issuesForHomeDbCount = allIssues.filter(
      (issue) =>
        (!selectedFinding || issue.findings.includes(selectedFinding)) &&
        issue.bug_id.toLowerCase().includes(searchTerm)
    );
    const homeDbCount = issuesForHomeDbCount.reduce((acc, issue) => {
      acc[issue.source] = (acc[issue.source] || 0) + 1;
      return acc;
    }, {});

    homeDbFilterOptions.innerHTML = `<div class="filter-option" data-value="">All (${issuesForHomeDbCount.length})</div>`;
    for (const homeDb of Object.keys(issuesByHomeDb).sort()) {
      const count = homeDbCount[homeDb] || 0;
      const option = document.createElement("div");
      option.className = "filter-option";
      option.dataset.value = homeDb;
      option.dataset.count = count;
      option.textContent = `${homeDb} (${count})`;
      homeDbFilterOptions.appendChild(option);
    }
    if (selectedHomeDb) {
      const selectedOption = homeDbFilterOptions.querySelector(
        `[data-value="${selectedHomeDb}"]`
      );
      if (selectedOption) {
        const { value, count } = selectedOption.dataset;
        homeDbFilterSelected.textContent = `${value} (${count} issues)`;
      }
    } else {
      homeDbFilterSelected.textContent = `All (${issuesForHomeDbCount.length} issues)`;
    }
  }

  function sortIssues() {
    filteredIssues.sort((a, b) => {
      const dateA = new Date(a.last_attempt);
      const dateB = new Date(b.last_attempt);
      if (sortDirection === "asc") {
        return dateA - dateB;
      } else {
        return dateB - dateA;
      }
    });
  }

  function displayIssues() {
    const tableBody = document
      .getElementById("issues-table")
      .getElementsByTagName("tbody")[0];
    tableBody.innerHTML = "";

    const startIndex = (currentPage - 1) * issuesPerPage;
    const endIndex = startIndex + issuesPerPage;
    const paginatedIssues = filteredIssues.slice(startIndex, endIndex);

    if (paginatedIssues.length === 0) {
      if (dataLoadingComplete) {
        tableBody.innerHTML = '<tr><td colspan="3">No issues found.</td></tr>';
      } else {
        tableBody.innerHTML =
          '<tr><td colspan="3">Loading data...</td></tr>';
      }
    } else {
      paginatedIssues.forEach((issue) => {
        let row = tableBody.insertRow();
        row.classList.add("clickable");
        row.addEventListener("click", () => {
          openCombinedView(issue.bug_id);
        });

        let cell1 = row.insertCell();
        let cell2 = row.insertCell();
        let cell3 = row.insertCell();

        const bugLink = document.createElement("a");
        bugLink.href = `https://api.test.osv.dev/v1/vulns/${issue.bug_id}`;
        bugLink.textContent = issue.bug_id;
        bugLink.addEventListener("click", (e) => {
          e.stopPropagation();
          openCombinedView(issue.bug_id);
          e.preventDefault();
        });
        cell1.appendChild(bugLink);

        const findingsContainer = document.createElement("div");
        issue.findings.forEach((finding) => {
          const findingSpan = document.createElement("span");
          findingSpan.textContent = finding.replace("IMPORT_FINDING_TYPE_", "");
          findingSpan.className = "finding-tag";
          findingsContainer.appendChild(findingSpan);
        });
        cell2.appendChild(findingsContainer);

        cell3.textContent = new Date(issue.last_attempt).toLocaleString();
      });
    }
    setupPagination();
  }

  function setupPagination() {
    const paginationControls = document.getElementById("pagination-controls");
    paginationControls.innerHTML = "";
    const pageCount = Math.ceil(filteredIssues.length / issuesPerPage);

    if (pageCount <= 1) return;

    const prevButton = document.createElement("button");
    prevButton.textContent = "Previous";
    prevButton.disabled = currentPage === 1;
    prevButton.addEventListener("click", () => {
      if (currentPage > 1) {
        currentPage--;
        displayIssues();
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
        displayIssues();
      }
    });
    paginationControls.appendChild(nextButton);
  }

  function sanitiseBugId(bugId) {
    // This regular expression keeps only letters, numbers, hyphens, and colons.
    return bugId.replace(/[^a-zA-Z0-9-:]/g, "");
  }

  function openCombinedView(bugId) {
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

    const tabContent = document.createElement("div");
    tabContent.className = "tab-content";
    tabContent.id = tabId;

    tabContent.innerHTML = `
      <div class="details-grid">
          <div class="details-column">
              <h2>Vulnerability Data</h2>
              <pre id="${vulnJsonId}" class="json-pre">Loading...</pre>
          </div>
          <div class="details-column">
              <h2>Linter Findings</h2>
              <div id="${findingsJsonId}" class="json-pre">Loading...</div>
          </div>
      </div>
                `;

    tabsContent.appendChild(tabContent);
    setActiveTab(tabId);

    // Fetch vuln data with the original bugId
    fetch(`https://api.test.osv.dev/v1/vulns/${bugId}`)
      .then((res) =>
        res.ok ? res.json() : { error: `Failed to load: ${res.status}` }
      )
      .then((data) => {
        document.getElementById(vulnJsonId).textContent = 
          JSON.stringify(data, null, 2);
      })
      .catch((err) => {
        document.getElementById(
          vulnJsonId
        ).textContent = `Error: ${err.message}`;
      });

    // Display finding data
    const details = findingDetails[bugId];
    const findingsEl = document.getElementById(findingsJsonId);
    if (details?.length) {
      findingsEl.textContent = ''; // Clear "Loading..."
      findingsEl.appendChild(formatFindings(details));
      findingsEl.classList.remove("json-pre");
    } else {
      findingsEl.textContent =
          "No linter findings available for this vulnerability.";
    }
  }

  function formatFindings(details) {
    const table = document.createElement('table');
    table.className = 'findings-table';
    table.innerHTML = '<thead><tr><th>Code</th><th>Message</th></tr></thead>';
    const tbody = table.createTBody();

    details.forEach((finding) => {
      const row = tbody.insertRow();
      const codeCell = row.insertCell();
      codeCell.textContent = finding.Code || '';
      const messageCell = row.insertCell();
      messageCell.textContent = finding.Message || '';
    });

    return table;
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

  function toggleFilter(filterName) {
    const options = document.getElementById(`${filterName}-filter-options`);
    const isVisible = options.style.display === "block";

    // Hide all filter options first
    document
      .querySelectorAll(".filter-option-container")
      .forEach((el) => (el.style.display = "none"));

    if (!isVisible) {
      options.style.display = "block";
    }
  }

  document.addEventListener("click", function (e) {
    if (!e.target.closest(".filter-container")) {
      document
        .querySelectorAll(".filter-option-container")
        .forEach((el) => (el.style.display = "none"));
    }
  });

  loadData();
});
