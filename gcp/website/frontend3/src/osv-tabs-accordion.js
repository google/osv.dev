class OsvTabsAccordion extends HTMLElement {
  constructor() {
    super();
    this.breakpoint = 500;
    this.mediaQuery = null;
    this.headers = [];
    this.panels = [];
    this.activeIndex = 0;
  }

  connectedCallback() {
    this.breakpoint = parseInt(this.getAttribute("breakpoint")) || 500;
    this.collectHeadersAndPanels();
    this.setupMediaQuery();
    this.updateAffordance();
    this.setupEventListeners();
  }

  disconnectedCallback() {
    if (this.mediaQuery) {
      this.mediaQuery.removeEventListener("change", this.boundUpdateAffordance);
    }
  }

  collectHeadersAndPanels() {
    this.headers = [];
    this.panels = [];

    const children = Array.from(this.children);
    for (let i = 0; i < children.length; i++) {
      const child = children[i];
      if (child.matches("h2, h3")) {
        const nextSibling = children[i + 1];
        if (nextSibling && nextSibling.matches("div")) {
          this.headers.push(child);
          this.panels.push(nextSibling);
        }
      }
    }
  }

  setupMediaQuery() {
    this.mediaQuery = window.matchMedia(
      `(min-width: ${this.breakpoint + 1}px)`
    );
    this.boundUpdateAffordance = () => this.updateAffordance();
    this.mediaQuery.addEventListener("change", this.boundUpdateAffordance);
  }

  setupEventListeners() {
    this.headers.forEach((header, index) => {
      header.addEventListener("click", (e) => this.handleHeaderClick(index, e));
      header.addEventListener("keydown", (e) => this.handleKeydown(index, e));
    });
  }

  updateAffordance() {
    const isDesktop = this.mediaQuery.matches;
    const affordance = isDesktop ? "tab-bar" : "collapse";
    this.setAttribute("affordance", affordance);

    if (isDesktop) {
      this.renderTabs();
    } else {
      this.renderAccordion();
    }
  }

  renderTabs() {
    this.headers.forEach((header, index) => {
      const isActive = index === this.activeIndex;
      header.setAttribute("tabindex", isActive ? "0" : "-1");
      header.setAttribute("role", "tab");
      header.setAttribute("aria-selected", isActive ? "true" : "false");
      header.removeAttribute("aria-expanded");
      header.removeAttribute("expanded");
    });

    this.panels.forEach((panel, index) => {
      const isActive = index === this.activeIndex;
      panel.setAttribute("role", "tabpanel");
      panel.style.display = isActive ? "" : "none";
      panel.removeAttribute("aria-hidden");
    });
  }

  renderAccordion() {
    // By default, expand all panels in accordion mode
    this.headers.forEach((header, index) => {
      const panel = this.panels[index];
      panel.style.display = "";

      header.setAttribute("role", "button");
      header.setAttribute("tabindex", "0");
      header.setAttribute("aria-expanded", "true");
      header.setAttribute("expanded", "");
      header.removeAttribute("aria-selected");
    });

    this.panels.forEach((panel) => {
      panel.setAttribute("role", "region");
      panel.removeAttribute("aria-hidden");
    });
  }

  handleHeaderClick(index, event) {
    if (!this.headers[index].contains(event.target)) {
      return;
    }

    const affordance = this.getAttribute("affordance");

    if (affordance === "tab-bar") {
      this.activeIndex = index;
      this.renderTabs();
    } else {
      const panel = this.panels[index];
      const header = this.headers[index];
      const isExpanded = panel.style.display !== "none";

      panel.style.display = isExpanded ? "none" : "";
      header.setAttribute("aria-expanded", isExpanded ? "false" : "true");
      if (isExpanded) {
        header.removeAttribute("expanded");
      } else {
        header.setAttribute("expanded", "");
      }
    }
  }

  handleKeydown(index, event) {
    const affordance = this.getAttribute("affordance");

    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      this.handleHeaderClick(index, { target: this.headers[index] });
    }

    if (affordance === "tab-bar") {
      if (event.key === "ArrowRight" || event.key === "ArrowDown") {
        event.preventDefault();
        const nextIndex = (index + 1) % this.headers.length;
        this.activeIndex = nextIndex;
        this.renderTabs();
        this.headers[nextIndex].focus();
      } else if (event.key === "ArrowLeft" || event.key === "ArrowUp") {
        event.preventDefault();
        const prevIndex =
          (index - 1 + this.headers.length) % this.headers.length;
        this.activeIndex = prevIndex;
        this.renderTabs();
        this.headers[prevIndex].focus();
      }
    }
  }
}

customElements.define("osv-tabs-accordion", OsvTabsAccordion);
