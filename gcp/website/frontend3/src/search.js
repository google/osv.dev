import { submitForm } from './index.js';

const MIN_QUERY_LENGTH = 3;
const NAV_SEARCH_CLOSE_FALLBACK_MS = 380;

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
      if (window.OSVSearchInstance.cacheHandler) {
        document.removeEventListener('turbo:before-cache', window.OSVSearchInstance.cacheHandler);
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
    this.cacheHandler = this.preCache.bind(this);

    document.addEventListener('click', this.documentClickHandler);
    document.addEventListener('keydown', this.documentKeydownHandler);
    document.addEventListener('turbo:before-cache', this.cacheHandler);
  }

  detachElementHandlers(searchToggle, searchForm) {
    if (searchToggle && searchToggle.__osvSearchToggleHandler) {
      searchToggle.removeEventListener('click', searchToggle.__osvSearchToggleHandler);
      delete searchToggle.__osvSearchToggleHandler;
    }
    if (searchForm && searchForm.__osvSearchSubmitHandler) {
      searchForm.removeEventListener('submit', searchForm.__osvSearchSubmitHandler);
      delete searchForm.__osvSearchSubmitHandler;
    }
  }

  preCache() {
    this.detachElementHandlers(this.container?.toggle, this.container?.form);
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

    this.detachElementHandlers(searchToggle, searchForm);

    const toggleHandler = (e) => {
      e.preventDefault();
      const isActive = searchForm.classList.contains('active');
      
      if (isActive) {
        this.closeSearch();
      } else {
        this.openSearch();
      }
    };
    searchToggle.addEventListener('click', toggleHandler);
    searchToggle.__osvSearchToggleHandler = toggleHandler;

    const submitHandler = (e) => {
      const query = searchInput.value.trim();
      if (!query) {
        e.preventDefault();
      }
    };
    searchForm.addEventListener('submit', submitHandler);
    searchForm.__osvSearchSubmitHandler = submitHandler;
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
    this.suggestionsContainer = this.input?.closest('.search-suggestions-container');
    this.isNavContext = Boolean(this.suggestionsContainer?.closest('.search-container-nav'));
    this.mountMode = this.isNavContext ? 'inline' : 'portal';
    this.suggestionsElement = null;
    this.selectedIndex = -1;
    this.currentSuggestions = [];
    this.debounceTimer = null;
    this.isDestroyed = false;
    this.inputHandler = null;
    this.keydownHandler = null;
    this.blurHandler = null;
    this.visiblePositionUpdateHandler = () => {
      if (this.isDestroyed || !this.suggestionsElement || this.suggestionsElement.classList.contains('search-suggestions--hidden')) {
        return;
      }
      this.updatePosition();
    };
    
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
    
    if (this.isNavContext) {
      this.suggestionsElement.classList.add('search-suggestions--nav');
    } else if (this.suggestionsContainer?.closest('.list-page')) {
      this.suggestionsElement.classList.add('search-suggestions--list-page');
    }
    
    // Add a unique identifier to track this element for cleanup
    this.managerId = `suggestions-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    this.suggestionsElement.dataset.managerId = this.managerId;
    
    this.appendSuggestionsElement();
  }
  
  appendSuggestionsElement() {
    if (this.isDestroyed) return;

    if (this.mountMode === 'inline' && this.suggestionsContainer) {
      this.suggestionsContainer.appendChild(this.suggestionsElement);
      return;
    }

    if (document.body) {
      document.body.appendChild(this.suggestionsElement);
    } else {
      // If body is not ready, try again shortly.
      setTimeout(() => this.appendSuggestionsElement(), 10);
    }
  }

  setupEventListeners() {
    if (!this.input) return;

    this.inputHandler = () => {
      if (this.isDestroyed) return;
      this.selectedIndex = -1;
      clearTimeout(this.debounceTimer);
      this.debounceTimer = setTimeout(() => this.handleInput(), 300);
    };
    this.keydownHandler = (e) => this.handleKeydown(e);
    this.blurHandler = () => setTimeout(() => this.hide(), 200);

    this.input.addEventListener('input', this.inputHandler);
    this.input.addEventListener('keydown', this.keydownHandler);
    this.input.addEventListener('blur', this.blurHandler);

    if (this.mountMode === 'portal') {
      window.addEventListener('resize', this.visiblePositionUpdateHandler);
      window.addEventListener('scroll', this.visiblePositionUpdateHandler, true);
    }
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
    if (this.isDestroyed) return;
    if (!this.currentSuggestions.length) {
      this.hide();
      return;
    }
    this.updatePosition();
    this.render();
    this.suggestionsElement.classList.remove('search-suggestions--hidden');
    // Add active class to container for styling
    this.input.closest('.search-suggestions-container')?.classList.add('suggestions-active');
  }

  hide() {
    if (this.isDestroyed) return;
    if (this.suggestionsElement) {
      this.suggestionsElement.classList.add('search-suggestions--hidden');
    }
    this.selectedIndex = -1;
    // Remove active class from container
    this.input.closest('.search-suggestions-container')?.classList.remove('suggestions-active');
  }

  updatePosition() {
    if (!this.suggestionsElement) {
      return;
    }

    if (this.mountMode === 'inline') {
      this.suggestionsElement.style.left = '';
      this.suggestionsElement.style.top = '';
      this.suggestionsElement.style.width = '';
      return;
    }

    const anchorRect = (this.suggestionsContainer || this.input).getBoundingClientRect();
    this.suggestionsElement.style.left = `${anchorRect.left + window.scrollX}px`;
    this.suggestionsElement.style.top = `${anchorRect.bottom + window.scrollY}px`;
    this.suggestionsElement.style.width = `${anchorRect.width}px`;
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

    const form = this.input.closest('form');
    if (!form) {
      return;
    }

    if (this.isNavContext) {
      if (window.OSVSearchInstance && typeof window.OSVSearchInstance.closeSearch === 'function') {
        window.OSVSearchInstance.closeSearch();
      } else {
        form.classList.remove('active');
        const searchContainer = form.closest('.search-container-nav');
        const searchToggle = searchContainer?.querySelector('.search-toggle');
        searchToggle?.classList.remove('active');
        searchToggle?.setAttribute('aria-expanded', 'false');
      }

      this.submitAfterNavClose(form);
      return;
    }

    submitForm(form);
  }

  submitAfterNavClose(form) {
    let hasSubmitted = false;
    let fallbackTimer = null;

    const submitOnce = () => {
      if (hasSubmitted) {
        return;
      }

      hasSubmitted = true;
      form.removeEventListener('transitionend', onTransitionEnd);

      if (fallbackTimer) {
        clearTimeout(fallbackTimer);
      }

      submitForm(form);
    };

    const onTransitionEnd = (event) => {
      if (event.target !== form || event.propertyName !== 'width') {
        return;
      }

      submitOnce();
    };

    form.addEventListener('transitionend', onTransitionEnd);
    fallbackTimer = setTimeout(submitOnce, NAV_SEARCH_CLOSE_FALLBACK_MS);
  }

  destroy() {
    this.isDestroyed = true;
    clearTimeout(this.debounceTimer);

    if (this.input) {
      if (this.inputHandler) {
        this.input.removeEventListener('input', this.inputHandler);
      }
      if (this.keydownHandler) {
        this.input.removeEventListener('keydown', this.keydownHandler);
      }
      if (this.blurHandler) {
        this.input.removeEventListener('blur', this.blurHandler);
      }
    }

    if (this.mountMode === 'portal') {
      window.removeEventListener('resize', this.visiblePositionUpdateHandler);
      window.removeEventListener('scroll', this.visiblePositionUpdateHandler, true);
    }
    
    if (this.suggestionsElement) {
      this.suggestionsElement.remove();
      this.suggestionsElement = null;
    }
    
    // Clear references
    this.input = null;
    this.currentSuggestions = [];
  }
}
