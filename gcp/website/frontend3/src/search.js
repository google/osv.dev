import { submitForm } from './index.js';

export class ExpandableSearch {
  constructor() {
    this.containers = [];
    this.suggestionsManagers = new Map(); // Track suggestions managers per container
    
    this.cleanupExistingInstances();
    this.setupGlobalListeners();
    this.initializeSearch();
  }
  
  cleanupExistingInstances() {
    // If there's a global instance, clean it up
    if (window.OSVSearchInstance) {
      if (window.OSVSearchInstance.documentClickHandler) {
        document.removeEventListener('click', window.OSVSearchInstance.documentClickHandler);
      }
      if (window.OSVSearchInstance.documentKeydownHandler) {
        document.removeEventListener('keydown', window.OSVSearchInstance.documentKeydownHandler);
      }
      // Cleanup existing suggestions managers (to prevent old suggestion dropdowns from persisting)
      if (window.OSVSearchInstance.suggestionsManagers) {
        window.OSVSearchInstance.suggestionsManagers.forEach(manager => {
          manager.destroy();
        });
        window.OSVSearchInstance.suggestionsManagers.clear();
      }
    }
    
    // Store this instance globally
    window.OSVSearchInstance = this;
  }
  
  setupGlobalListeners() {
    this.documentClickHandler = this.handleDocumentClick.bind(this);
    this.documentKeydownHandler = this.handleDocumentKeydown.bind(this);
    
    document.addEventListener('click', this.documentClickHandler);
    document.addEventListener('keydown', this.documentKeydownHandler);
  }
  
  handleDocumentClick(e) {
    this.containers.forEach(container => {
      if (container && container.element && 
          !container.element.contains(e.target) && 
          container.form.classList.contains('active')) {
        this.closeSearch(container);
      }
    });
  }
  
  handleDocumentKeydown(e) {
    // Close any open search on escape key
    if (e.key === 'Escape') {
      this.containers.forEach(container => {
        if (container && container.form && 
            container.form.classList.contains('active')) {
          this.closeSearch(container);
        }
      });
    }
  }

  initializeSearch() {
    this.initializeSearchContainer('.search-container-nav');
  }
  
  initializeSearchContainer(containerSelector) {
    const searchContainer = document.querySelector(containerSelector);
    if (!searchContainer) {
      return;
    }

    const searchForm = searchContainer.querySelector('.search-form');
    const searchToggle = searchContainer.querySelector('.search-toggle');
    const searchInput = searchContainer.querySelector('.search-input');
    
    if (!searchForm || !searchToggle || !searchInput) {
      return;
    }

    const containerInfo = {
      element: searchContainer,
      form: searchForm,
      toggle: searchToggle,
      input: searchInput
    };
    
    this.containers.push(containerInfo);

    const toggleHandler = (e) => {
      e.preventDefault();
      const isActive = searchForm.classList.contains('active');
      
      if (isActive) {
        this.closeSearch(containerInfo);
      } else {
        this.openSearch(containerInfo);
      }
    };
    
    if (!searchToggle.hasAttribute('data-search-initialized')) {
      searchToggle.addEventListener('click', toggleHandler);
      searchToggle.setAttribute('data-search-initialized', 'true');
    }

    const submitHandler = (e) => {
      const query = searchInput.value.trim();
      if (!query) {
        e.preventDefault();
      }
    };
    
    if (!searchForm.hasAttribute('data-search-initialized')) {
      searchForm.addEventListener('submit', submitHandler);
      searchForm.setAttribute('data-search-initialized', 'true');
    }
  }

  openSearch(container) {
    if (!container || !container.form) return;
    
    container.form.classList.add('active');
    container.toggle.classList.add('active');
    container.toggle.setAttribute('aria-expanded', 'true');
    
    setTimeout(() => {
      if (container.input) {
        container.input.focus();
        // Create suggestions only when search is loaded
        if (!this.suggestionsManagers.has(container.input)) {
          const suggestionsManager = new SearchSuggestionsManager(container.input);
          this.suggestionsManagers.set(container.input, suggestionsManager);
        }
      }
    }, 100);
  }

  closeSearch(container) {
    if (!container || !container.form) return;
    
    container.form.classList.remove('active');
    container.toggle.classList.remove('active');
    container.toggle.setAttribute('aria-expanded', 'false');
    
    if (container.input) {
      container.input.blur();
      // Hide suggestions when closing search
      const suggestionsManager = this.suggestionsManagers.get(container.input);
      if (suggestionsManager) {
        suggestionsManager.hide();
      }
    }
  }
}

// ============= Search Suggestions Manager =============

export class SearchSuggestionsManager {
  constructor(inputElement) {
    this.input = inputElement;
    this.suggestionsElement = null;
    this.selectedIndex = -1;
    this.currentSuggestions = [];
    this.debounceTimer = null;
    this.isDestroyed = false;
    
    this.cleanupOrphanedElements();
    
    this.init();
  }

  init() {
    this.createSuggestionsElement();
    this.setupEventListeners();
  }

  cleanupOrphanedElements() {
    const orphanedElements = document.querySelectorAll('.search-suggestions');
    orphanedElements.forEach(element => {
      if (!element.dataset.managerId) {
        element.remove();
      }
    });
  }

  createSuggestionsElement() {
    if (this.suggestionsElement) {
      return;
    }
    
    this.suggestionsElement = document.createElement('div');
    this.suggestionsElement.classList.add('search-suggestions');
    this.suggestionsElement.style.display = 'none';
    
    // Add a unique identifier to track this element
    this.managerId = `suggestions-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    this.suggestionsElement.dataset.managerId = this.managerId;
    
    // Ensure document.body exists before appending
    if (document.body) {
      document.body.appendChild(this.suggestionsElement);
    } else {
      const checkBody = () => {
        if (document.body && !this.isDestroyed) {
          document.body.appendChild(this.suggestionsElement);
        } else if (!this.isDestroyed) {
          setTimeout(checkBody, 10);
        }
      };
      checkBody();
    }
  }

  setupEventListeners() {
    if (!this.input) return;
    
    this.input.addEventListener('input', () => {
      if (this.isDestroyed) return;
      this.selectedIndex = -1;
      clearTimeout(this.debounceTimer);
      this.debounceTimer = setTimeout(() => this.handleInput(), 300);
    });

    this.input.addEventListener('keydown', (e) => this.handleKeydown(e));
    this.input.addEventListener('blur', () => setTimeout(() => this.hide(), 200));
  }

  async handleInput() {
    if (this.isDestroyed) return;
    
    const query = this.input.value.trim();
    
    if (query.length < 2) {
      this.hide();
      return;
    }
    
    try {
      const response = await fetch(`/api/search_suggestions?q=${encodeURIComponent(query)}`);
      if (this.isDestroyed) return; 
      
      const data = await response.json();
      this.currentSuggestions = data.suggestions || [];
      this.show();
    } catch (error) {
      console.error('Error fetching suggestions:', error);
      this.hide();
    }
  }

  handleKeydown(e) {
    if (this.isDestroyed || !this.suggestionsElement || this.suggestionsElement.style.display === 'none') return;

    switch (e.key) {
      case 'ArrowDown':
        e.preventDefault();
        this.selectedIndex = Math.min(this.selectedIndex + 1, this.currentSuggestions.length - 1);
        this.updateSelection();
        break;
      case 'ArrowUp':
        e.preventDefault();
        this.selectedIndex = Math.max(this.selectedIndex - 1, -1);
        this.updateSelection();
        break;
      case 'Enter':
        if (this.selectedIndex >= 0) {
          e.preventDefault();
          this.selectSuggestion(this.currentSuggestions[this.selectedIndex]);
        }
        break;
      case 'Escape':
        this.hide();
        break;
    }
  }

  show() {
    if (!this.currentSuggestions.length) {
      this.hide();
      return;
    }

    this.updatePosition();
    this.render();
    this.suggestionsElement.style.display = 'block';
  }

  hide() {
    if (this.suggestionsElement) {
      this.suggestionsElement.style.display = 'none';
    }
    this.selectedIndex = -1;
  }

  updatePosition() {
    const rect = this.input.getBoundingClientRect();
    const queryContainer = this.input.closest('.query-container');
    const isNavbarSearch = this.input.closest('.search-container-nav');

    if (isNavbarSearch) {
      // Navbar search
      const searchForm = this.input.closest('.search-form');
      const formRect = searchForm.getBoundingClientRect();

      this.suggestionsElement.style.left = `${formRect.left}px`;
      this.suggestionsElement.style.top = `${formRect.bottom}px`;
      this.suggestionsElement.style.width = `${formRect.width}px`;
    } else if (queryContainer) {
      // Main search
      const containerRect = queryContainer.getBoundingClientRect();
      this.suggestionsElement.style.left = `${containerRect.left}px`;
      this.suggestionsElement.style.top = `${containerRect.bottom}px`;
      this.suggestionsElement.style.width = `${containerRect.width}px`;
    } else {
      // Fallback
      this.suggestionsElement.style.left = `${rect.left}px`;
      this.suggestionsElement.style.top = `${rect.bottom}px`;
      this.suggestionsElement.style.width = `${rect.width}px`;
    }
  }

  render() {
    this.suggestionsElement.innerHTML = '';
    
    this.currentSuggestions.forEach((suggestion, index) => {
      const item = document.createElement('div');
      item.classList.add('search-suggestions__item');
      item.textContent = suggestion;
      
      item.addEventListener('click', () => this.selectSuggestion(suggestion));
      
      this.suggestionsElement.appendChild(item);
    });
    
    this.updateSelection();
  }

  updateSelection() {
    const items = this.suggestionsElement.querySelectorAll('.search-suggestions__item');
    items.forEach((item, index) => {
      item.classList.toggle('search-suggestions__item--selected', index === this.selectedIndex);
    });
  }

  selectSuggestion(suggestion) {
    this.input.value = suggestion;
    this.hide();
    submitForm(this.input.closest('form'));
  }

  destroy() {
    this.isDestroyed = true;
    clearTimeout(this.debounceTimer);
    
    if (this.suggestionsElement) {
      this.suggestionsElement.remove();
      this.suggestionsElement = null;
    }
    
    // Clear references
    this.input = null;
    this.currentSuggestions = [];
  }
}
