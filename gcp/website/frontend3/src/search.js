import { submitForm } from './index.js';

const MIN_QUERY_LENGTH = 3;

export class ExpandableSearch {
  constructor() {
    this.container = null;
    this.suggestionsManager = null;
    
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
      // Cleanup existing suggestions manager
      if (window.OSVSearchInstance.suggestionsManager) {
        window.OSVSearchInstance.suggestionsManager.destroy();
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
    if (this.container && this.container.element && 
        !this.container.element.contains(e.target) && 
        this.container.form.classList.contains('active')) {
      this.closeSearch();
    }
  }

  handleDocumentKeydown(e) {
    // Close any open search on escape key
    if (e.key === 'Escape') {
      if (this.container && this.container.form && 
          this.container.form.classList.contains('active')) {
        this.closeSearch();
      }
    }
  }

  initializeSearch() {
    const searchContainer = document.querySelector('.search-container-nav');
    if (!searchContainer) {
      return;
    }

    const searchForm = searchContainer.querySelector('.search-form');
    const searchToggle = searchContainer.querySelector('.search-toggle');
    const searchInput = searchContainer.querySelector('.search-input');
    
    if (!searchForm || !searchToggle || !searchInput) {
      return;
    }

    this.container = {
      element: searchContainer,
      form: searchForm,
      toggle: searchToggle,
      input: searchInput
    };

    const toggleHandler = (e) => {
      e.preventDefault();
      const isActive = searchForm.classList.contains('active');
      
      if (isActive) {
        this.closeSearch();
      } else {
        this.openSearch();
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

  openSearch() {
    if (!this.container || !this.container.form) return;
    
    this.container.form.classList.add('active');
    this.container.toggle.classList.add('active');
    this.container.toggle.setAttribute('aria-expanded', 'true');
    
    setTimeout(() => {
      if (this.container.input) {
        this.container.input.focus();
        // Create suggestions only when search is opened
        if (!this.suggestionsManager) {
          this.suggestionsManager = new SearchSuggestionsManager(this.container.input);
        }
      }
    }, 100);
  }

  closeSearch() {
    if (!this.container || !this.container.form) return;
    
    this.container.form.classList.remove('active');
    this.container.toggle.classList.remove('active');
    this.container.toggle.setAttribute('aria-expanded', 'false');
    
    if (this.container.input) {
      this.container.input.blur();
      // Hide suggestions when closing search
      if (this.suggestionsManager) {
        this.suggestionsManager.hide();
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
    
    this.init();
  }

  init() {
    this.createSuggestionsElement();
    this.setupEventListeners();
  }

  createSuggestionsElement() {
    if (this.suggestionsElement) {
      return;
    }
    
    this.suggestionsElement = document.createElement('div');
    this.suggestionsElement.classList.add('search-suggestions', 'search-suggestions--hidden');
    
    // Add a unique identifier to track this element for cleanup
    this.managerId = `suggestions-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    this.suggestionsElement.dataset.managerId = this.managerId;
    
    this.appendSuggestionsElement();
  }
  
  /**
   * Appends the suggestions element to the document body.
   * If the body is not yet available, it waits and retries.
   */
  appendSuggestionsElement() {
    if (this.isDestroyed) return;

    if (document.body) {
      document.body.appendChild(this.suggestionsElement);
    } else {
      // If body is not ready, try again shortly.
      setTimeout(() => this.appendSuggestionsElement(), 10);
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
    this.input.addEventListener('blur', () => setTimeout(() => this.hide(), 200)); // Delay to allow click events on suggestions
  }

  async handleInput() {
    if (this.isDestroyed) return;
    
    const query = this.input.value.trim();
    
    if (query.length < MIN_QUERY_LENGTH) {
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
    if (this.isDestroyed || !this.suggestionsElement || this.suggestionsElement.classList.contains('search-suggestions--hidden')) return;

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
    this.suggestionsElement.classList.remove('search-suggestions--hidden');
  }

  hide() {
    if (this.suggestionsElement) {
      this.suggestionsElement.classList.add('search-suggestions--hidden');
    }
    this.selectedIndex = -1;
  }

  updatePosition() {
    const rect = this.input.getBoundingClientRect();
    
    // Look for the designated suggestions container
    const suggestionContainer = this.input.closest('.search-suggestions-container');

    if (suggestionContainer) {
      // Use the designated suggestions container
      const containerRect = suggestionContainer.getBoundingClientRect();
      this.suggestionsElement.style.left = `${containerRect.left}px`;
      this.suggestionsElement.style.top = `${containerRect.bottom}px`;
      this.suggestionsElement.style.width = `${containerRect.width}px`;
    } else {
      console.warn('No .search-suggestions-container found. Add this class to the desired parent element to control suggestions positioning.');
      // Fallback to input element positioning
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
