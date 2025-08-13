import "./linter.scss";

document.addEventListener("DOMContentLoaded", function () {
  let allIssues = [];
  let issuesByEcosystem = {};
  let filteredIssues = [];
  let findingDetails = {};
  const issuesPerPage = 15;
  let currentPage = 1;
  let sortDirection = "desc";

  const globalLoader = document.getElementById("global-loader");
  const searchInput = document.getElementById("search-input");
  const modifiedHeader = document.getElementById("modified-header");
  const tabBarContainer = document.querySelector(".tab-bar-container");
  const tabSwitch = document.getElementById("tab-switch");
  const tabsContent = document.getElementById("tabs-content");

  const ecosystemFilter = document.getElementById("ecosystem-filter");
  const ecosystemFilterSelected = document.getElementById(
    "ecosystem-filter-selected"
  );
  const ecosystemFilterOptions = document.getElementById(
    "ecosystem-filter-options"
  );

  const findingsFilter = document.getElementById("findings-filter");
  const findingsFilterSelected = document.getElementById(
    "findings-filter-selected"
  );
  const findingsFilterOptions = document.getElementById(
    "findings-filter-options"
  );

  let selectedEcosystem = "";
  let selectedFinding = "";

  async function loadData() {
    globalLoader.classList.add("visible");

    // Get source names from github source_test.yaml file
    const response = await fetch(
      "https://raw.githubusercontent.com/google/osv.dev/master/source_test.yaml"
    );
    const yamlText = await response.text();
    const sources = jsyaml.load(yamlText);
    const sourceNames = sources.map((s) => s.name);

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
            if (!issuesByEcosystem[issue.source]) {
              issuesByEcosystem[issue.source] = [];
            }
            issuesByEcosystem[issue.source].push(issue);
          });
          applyFilters();
        })
        .catch((error) =>
          console.error("Error loading data from " + url, error)
        );
    });
    allPromises.push(...issuePromises);

    // Wait for all data fetching to complete
    Promise.allSettled(allPromises).then(() => {
      globalLoader.classList.remove("visible");
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

    ecosystemFilter.addEventListener("click", (e) => {
      e.stopPropagation();
      toggleFilter("ecosystem");
    });
    findingsFilter.addEventListener("click", (e) => {
      e.stopPropagation();
      toggleFilter("findings");
    });

    ecosystemFilterOptions.addEventListener("click", (e) => {
      if (e.target.classList.contains("filter-option")) {
        selectedEcosystem = e.target.dataset.value;
        ecosystemFilterSelected.textContent = e.target.textContent.replace(
          /\((\d+)\)/,
          `($1 issues)`
        );
        applyFilters();
      }
    });

    findingsFilterOptions.addEventListener("click", (e) => {
      if (e.target.classList.contains("filter-option")) {
        selectedFinding = e.target.dataset.value;
        findingsFilterSelected.textContent = e.target.textContent.replace(
          /\((\d+)\)/,
          `($1 issues)`
        );
        applyFilters();
      }
    });
  }

  function applyFilters() {
    const searchTerm = searchInput.value.toLowerCase();

    filteredIssues = allIssues.filter((issue) => {
      const bugIdMatch = issue.bug_id.toLowerCase().includes(searchTerm);
      const ecosystemMatch =
        !selectedEcosystem || issue.source === selectedEcosystem;
      const findingMatch =
        !selectedFinding || issue.findings.includes(selectedFinding);
      return bugIdMatch && ecosystemMatch && findingMatch;
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
        (!selectedEcosystem || issue.source === selectedEcosystem) &&
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
      const option = document.createElement("div");
      option.className = "filter-option";
      option.dataset.value = finding;
      option.textContent = `${finding.replace(
        "IMPORT_FINDING_TYPE_",
        ""
      )} (${count})`;
      findingsFilterOptions.appendChild(option);
    }
    if (!selectedFinding) {
      findingsFilterSelected.textContent = `All (${issuesForFindingsCount.length} issues)`;
    }

    // Update Ecosystem counts
    const issuesForEcosystemCount = allIssues.filter(
      (issue) =>
        (!selectedFinding || issue.findings.includes(selectedFinding)) &&
        issue.bug_id.toLowerCase().includes(searchTerm)
    );
    const ecosystemCount = issuesForEcosystemCount.reduce((acc, issue) => {
      acc[issue.source] = (acc[issue.source] || 0) + 1;
      return acc;
    }, {});

    ecosystemFilterOptions.innerHTML = `<div class="filter-option" data-value="">All (${issuesForEcosystemCount.length})</div>`;
    for (const ecosystem of Object.keys(issuesByEcosystem).sort()) {
      const count = ecosystemCount[ecosystem] || 0;
      const option = document.createElement("div");
      option.className = "filter-option";
      option.dataset.value = ecosystem;
      option.textContent = `${ecosystem} (${count})`;
      ecosystemFilterOptions.appendChild(option);
    }
    if (!selectedEcosystem) {
      ecosystemFilterSelected.textContent = `All (${issuesForEcosystemCount.length} issues)`;
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

    if (paginatedIssues.length === 0 && allIssues.length === 0) {
      tableBody.innerHTML = '<tr><td colspan="3">Loading data...</td></tr>';
    } else if (paginatedIssues.length === 0) {
      tableBody.innerHTML = '<tr><td colspan="3">No issues found.</td></tr>';
    } else {
      paginatedIssues.forEach((issue) => {
        let row = tableBody.insertRow();
        row.classList.add("clickable");
        row.addEventListener("click", (e) => {
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

  function openCombinedView(bugId) {
    const tabId = `details-${bugId}`;
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

    const vulnJsonId = `vuln-json-${bugId}`;
    const findingsJsonId = `findings-json-${bugId}`;

    const tabContent = document.createElement("div");
    tabContent.className = "tab-content";
    tabContent.id = tabId;

    // Create elements programmatically to avoid XSS
    const detailsGrid = document.createElement("div");
    detailsGrid.className = "details-grid";

    const vulnColumn = document.createElement("div");
    vulnColumn.className = "details-column";
    const vulnHeader = document.createElement("h2");
    vulnHeader.textContent = "Vulnerability Data";
    const vulnPre = document.createElement("pre");
    vulnPre.id = vulnJsonId;
    vulnPre.className = "json-pre";
    vulnPre.textContent = "Loading...";
    vulnColumn.appendChild(vulnHeader);
    vulnColumn.appendChild(vulnPre);

    const findingsColumn = document.createElement("div");
    findingsColumn.className = "details-column";
    const findingsHeader = document.createElement("h2");
    findingsHeader.textContent = "Linter Findings";
    const findingsPreEl = document.createElement("pre");
    findingsPreEl.id = findingsJsonId;
    findingsPreEl.className = "json-pre";
    findingsPreEl.textContent = "Loading...";
    findingsColumn.appendChild(findingsHeader);
    findingsColumn.appendChild(findingsPreEl);

    detailsGrid.appendChild(vulnColumn);
    detailsGrid.appendChild(findingsColumn);
    tabContent.appendChild(detailsGrid);

    tabsContent.appendChild(tabContent);
    setActiveTab(tabId);

    // Fetch vuln data
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
    const findingsPre = document.getElementById(findingsJsonId);
    if (details) {
      findingsPre.textContent = JSON.stringify(details, null, 2);
    } else {
      findingsPre.textContent =
        "No linter findings available for this vulnerability.";
    }
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
