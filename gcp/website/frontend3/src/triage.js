import "./triage.scss";
import "@material/web/textfield/filled-text-field.js";
import "@material/web/button/filled-button.js";
import "@material/web/progress/circular-progress.js";
import "@github/clipboard-copy-element";
import JSONFormatter from "json-formatter-js";

const COPY_ICON_RESET_MS = 1500;

document.addEventListener("DOMContentLoaded", () => {
  const vulnIdInput = document.getElementById("vuln-id-input");
  const loadBtn = document.getElementById("load-btn");
  const columns = document.querySelectorAll(".triage-column");

  function showCopyFeedback(copyButton) {
    const icon = copyButton.querySelector(".material-icons");
    clearTimeout(copyButton._copyResetTimer);
    icon.textContent = "check";
    copyButton.setAttribute("aria-label", "Copied");
    copyButton.title = "Copied";
    copyButton._copyResetTimer = setTimeout(() => {
      icon.textContent = "content_copy";
      copyButton.setAttribute("aria-label", copyButton.dataset.copyLabel);
      copyButton.title = copyButton.dataset.copyLabel;
    }, COPY_ICON_RESET_MS);
  }

  function setCopyContent(column, content) {
    const copyButton = column.querySelector(".triage-copy");
    const copySource = column.querySelector(".copy-json-source");
    const icon = copyButton.querySelector(".material-icons");
    const disabled = !content;

    clearTimeout(copyButton._copyResetTimer);
    icon.textContent = "content_copy";
    copyButton.setAttribute("aria-label", copyButton.dataset.copyLabel);
    copyButton.title = copyButton.dataset.copyLabel;
    copySource.value = content;
    copyButton.setAttribute("aria-disabled", disabled.toString());
    copyButton.tabIndex = disabled ? -1 : 0;
  }

  columns.forEach((column) => {
    const copyButton = column.querySelector(".triage-copy");
    copyButton.dataset.copyLabel = copyButton.getAttribute("aria-label");
    copyButton.addEventListener("clipboard-copy", () => {
      showCopyFeedback(copyButton);
    });
  });

  // Map selection values to their respective endpoints/paths
  const sourceConfigMap = {
    // External APIs
    "cve-org": {
      proxySource: "cve",
    },
    "nvd-api": {
      proxySource: "nvd",
    },
    // Test Instance
    "test-nvd": {
      proxySource: "test-nvd",
    },
    "test-cve5": {
      proxySource: "test-cve5",
    },
    "test-osv": {
      proxySource: "test-osv",
    },
    "test-nvd-metrics": {
      proxySource: "test-nvd-metrics",
    },
    "test-cve5-metrics": {
      proxySource: "test-cve5-metrics",
    },
    // Prod Instance
    "prod-nvd": {
      proxySource: "prod-nvd",
    },
    "prod-cve5": {
      proxySource: "prod-cve5",
    },
    "prod-osv": {
      proxySource: "prod-osv",
    },
    "prod-nvd-metrics": {
      proxySource: "prod-nvd-metrics",
    },
    "prod-cve5-metrics": {
      proxySource: "prod-cve5-metrics",
    },
    // API
    "api-test": {
      urlTemplate: "https://api.test.osv.dev/v1/vulns/{id}",
    },
    "api-prod": {
      urlTemplate: "https://api.osv.dev/v1/vulns/{id}",
    },
  };



  async function fetchData(sourceKey, vulnId) {
    const config = sourceConfigMap[sourceKey];
    let url;
    
    const safeId = encodeURIComponent(vulnId);

    if (config.proxySource) {
      url = `/triage/proxy?source=${encodeURIComponent(config.proxySource)}&id=${safeId}`;
    } else if (config.urlTemplate) {
      url = config.urlTemplate.replace("{id}", safeId);
    } else {
      throw new Error("Invalid configuration");
    }

    const response = await fetch(url);
    if (!response.ok) {
      throw new Error(response.status === 404 ? "Not Found" : `Error: ${response.statusText}`);
    }
    return response.json();
  }

  function updateColumn(column) {
    const select = column.querySelector(".source-select");
    const contentPre = column.querySelector(".json-content");
    const spinner = column.querySelector(".loading-spinner");
    const sourceKey = select.value;
    const vulnId = vulnIdInput.value.trim();

    if (!sourceKey) {
        contentPre.textContent = "Select a source to view content";
        setCopyContent(column, "");
        return;
    }

    if (!vulnId) {
      contentPre.textContent = "Please enter a Vulnerability ID";
      setCopyContent(column, "");
      return;
    }

    spinner.classList.remove("hidden");
    contentPre.textContent = "";
    setCopyContent(column, "");

      fetchData(sourceKey, vulnId)
        .then((data) => {
          contentPre.textContent = "";
          const formatter = new JSONFormatter(data, Infinity, { theme: "dark" });
          contentPre.appendChild(formatter.render());
          setCopyContent(column, JSON.stringify(data, null, 2));
        })
      .catch((error) => {
        contentPre.textContent = error.message;
        setCopyContent(column, "");
      })
      .finally(() => {
        spinner.classList.add("hidden");
      });
  }

  function updateUrlParams() {
    const url = new URL(window.location.href);
    const vulnId = vulnIdInput.value.trim();
    
    if (vulnId) {
      url.searchParams.set("id", vulnId.toUpperCase());
      url.searchParams.delete("cve");
    } else {
      url.searchParams.delete("id");
      url.searchParams.delete("cve");
    }
    
    columns.forEach((col, idx) => {
      const colNum = idx + 1;
      const select = col.querySelector(".source-select");
      if (select.value) {
        url.searchParams.set(`s${colNum}`, select.value);
      } else {
        url.searchParams.delete(`s${colNum}`);
      }
      url.searchParams.delete(`col${colNum}`);
      url.searchParams.delete(`source${colNum}`);
    });
    
    window.history.replaceState(null, "", url.toString());
  }

  loadBtn.addEventListener("click", () => {
    updateUrlParams();
    columns.forEach((col) => updateColumn(col));
  });

  // Also handle Enter key on the input field
  vulnIdInput.addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
          updateUrlParams();
          columns.forEach((col) => updateColumn(col));
      }
  });

  // Individual column updates when dropdown changes
  columns.forEach((col) => {
    const select = col.querySelector(".source-select");
    select.addEventListener("change", () => {
        updateUrlParams();
        if (vulnIdInput.value.trim()) {
            updateColumn(col);
        }
    });
  });

  // Check if a CVE/vulnerability ID query param is specified in the URL
  const urlParams = new URLSearchParams(window.location.search);
  const urlId = urlParams.get("id") || urlParams.get("cve");
  if (urlId) {
    vulnIdInput.value = urlId.toUpperCase();
    
    columns.forEach((col, idx) => {
      const colNum = idx + 1;
      const select = col.querySelector(".source-select");
      
      // Check for column-specific source query param
      const sourceParam = urlParams.get(`s${colNum}`) || 
                          urlParams.get(`col${colNum}`) || 
                          urlParams.get(`source${colNum}`);
                          
      if (sourceParam && sourceConfigMap[sourceParam]) {
        select.value = sourceParam;
      } else if (!select.value) {
        // Pre-populate reasonable defaults if no selection is set
        if (colNum === 1) select.value = "test-cve5";
        else if (colNum === 2) select.value = "test-nvd";
        else if (colNum === 3) select.value = "test-osv";
      }
      
      updateColumn(col);
    });
  }
});
