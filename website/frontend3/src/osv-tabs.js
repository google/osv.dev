class OsvTabs extends HTMLElement {
  constructor() {
    super();
    this.breakpoint = 500;
    this.mediaQuery = null;
    this.headers = [];
    this.panels = [];
    this.activeIndex = 0;
    this.headerListeners = null;

    // shadow DOM for tab-bar layout
    this.attachShadow({ mode: "open" });
    this.shadowRoot.innerHTML = `
      <style>
        :host([affordance="tab-bar"]) {
          display: block;
        }
        :host([affordance="tab-bar"]) .tab-list {
          display: flex;
          flex-wrap: wrap;
        }
        :host([affordance="tab-bar"]) ::slotted(*) {
          display: none;
        }
        :host([affordance="tab-bar"]) .tab-list ::slotted(h2),
        :host([affordance="tab-bar"]) .tab-list ::slotted(h3) {
          display: block;
        }
        :host([affordance="tab-bar"]) .panel-container ::slotted(div[data-panel-active]) {
          display: block;
        }
        :host([affordance="collapse"]) .tab-list {
          display: none;
        }
        :host([affordance="collapse"]) .panel-container {
          display: none;
        }
        :host([affordance="collapse"]) ::slotted(*) {
          display: block;
        }
      </style>
      <div class="tab-list" part="tab-list">
        <slot name="tab"></slot>
      </div>
      <div class="panel-container" part="panel-container">
        <slot name="panel"></slot>
      </div>
      <slot></slot>
    `;
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
    this.removeEventListeners();
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
    this.headerListeners = this.headers.map((header, index) => {
      const clickListener = (e) => this.handleHeaderClick(index, e);
      const keydownListener = (e) => this.handleKeydown(index, e);

      header.addEventListener("click", clickListener);
      header.addEventListener("keydown", keydownListener);

      return { header, clickListener, keydownListener };
    });
  }

  removeEventListeners() {
    if (this.headerListeners) {
      this.headerListeners.forEach(({ header, clickListener, keydownListener }) => {
        header.removeEventListener("click", clickListener);
        header.removeEventListener("keydown", keydownListener);
      });
      this.headerListeners = null;
    }
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
      header.setAttribute("slot", "tab");
      header.setAttribute("tabindex", isActive ? "0" : "-1");
      header.setAttribute("role", "tab");
      header.setAttribute("aria-selected", isActive ? "true" : "false");
      header.removeAttribute("aria-expanded");
      header.removeAttribute("expanded");
    });

    this.panels.forEach((panel, index) => {
      const isActive = index === this.activeIndex;
      panel.setAttribute("slot", "panel");
      panel.setAttribute("role", "tabpanel");
      if (isActive) {
        panel.setAttribute("data-panel-active", "");
      } else {
        panel.removeAttribute("data-panel-active");
      }
    });
  }

  renderAccordion() {
    this.headers.forEach((header, index) => {
      const panel = this.panels[index];

      header.removeAttribute("slot");
      header.removeAttribute("role");
      header.removeAttribute("aria-selected");
      header.setAttribute("tabindex", "0");
      header.setAttribute("aria-expanded", "true");
      header.setAttribute("expanded", "");

      panel.removeAttribute("slot");
      panel.removeAttribute("data-panel-active");
      panel.style.display = "";
    });

    this.panels.forEach((panel) => {
      panel.setAttribute("role", "region");
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

customElements.define("osv-tabs", OsvTabs);
