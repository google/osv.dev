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
    const prev = window.OSVSearchInstance;
    if (prev) {
      document.removeEventListener('click', prev.documentClickHandler);
      document.removeEventListener('keydown', prev.documentKeydownHandler);
      document.removeEventListener('turbo:before-cache', prev.cacheHandler);
      prev.suggestionsManager?.destroy();
    }
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

  detachElementHandler(element, event, handlerKey) {
    if (!element?.[handlerKey]) return;
    element.removeEventListener(event, element[handlerKey]);
    delete element[handlerKey];
  }

  preCache() {
    this.detachElementHandler(this.container?.toggle, 'click', '__osvSearchToggleHandler');
    this.detachElementHandler(this.container?.form, 'submit', '__osvSearchSubmitHandler');
  }

  isSearchActive() {
    return this.container?.form?.classList.contains('active') ?? false;
  }

  handleDocumentClick(e) {
    if (this.isSearchActive() && !this.container.element.contains(e.target)) {
      this.closeSearch();
    }
  }

  handleDocumentKeydown(e) {
    if (e.key === 'Escape' && this.isSearchActive()) {
      this.closeSearch();
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

    this.detachElementHandler(searchToggle, 'click', '__osvSearchToggleHandler');
    this.detachElementHandler(searchForm, 'submit', '__osvSearchSubmitHandler');

    const toggleHandler = (e) => {
      e.preventDefault();
      if (searchForm.classList.contains('active')) {
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
    if (!this.container?.form) return;
    const { form, toggle, input } = this.container;

    form.classList.add('active');
    toggle.classList.add('active');
    toggle.setAttribute('aria-expanded', 'true');

    setTimeout(() => {
      input?.focus();
      if (input && !this.suggestionsManager) {
        this.suggestionsManager = new SearchSuggestionsManager(input);
      }
    }, 100);
  }

  closeSearch() {
    if (!this.container?.form) return;
    const { form, toggle, input } = this.container;

    form.classList.remove('active');
    toggle.classList.remove('active');
    toggle.setAttribute('aria-expanded', 'false');

    input?.blur();
    this.suggestionsManager?.hide();
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
      if (!this.isSuggestionsVisible()) return;
      this.updatePosition();
    };

    this.createSuggestionsElement();
    this.setupEventListeners();
  }

  isSuggestionsVisible() {
    return !this.isDestroyed
      && this.suggestionsElement
      && !this.suggestionsElement.classList.contains('search-suggestions--hidden');
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
    
    this.appendSuggestionsElement();
  }
  
  appendSuggestionsElement() {
    if (this.isDestroyed) return;

    const parent = (this.mountMode === 'inline' && this.suggestionsContainer)
      ? this.suggestionsContainer
      : document.body;

    if (parent) {
      parent.appendChild(this.suggestionsElement);
    } else {
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
    if (!this.isSuggestionsVisible()) return;

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
    this.suggestionsContainer?.classList.add('suggestions-active');
  }

  hide() {
    if (this.isDestroyed) return;
    this.suggestionsElement?.classList.add('search-suggestions--hidden');
    this.selectedIndex = -1;
    this.suggestionsContainer?.classList.remove('suggestions-active');
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
    
    this.currentSuggestions.forEach((suggestion) => {
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
    if (!form) return;

    if (!this.isNavContext) {
      submitForm(form);
      return;
    }

    if (typeof window.OSVSearchInstance?.closeSearch === 'function') {
      window.OSVSearchInstance.closeSearch();
    } else {
      this.closeNavSearchManually(form);
    }

    this.submitAfterNavClose(form);
  }

  closeNavSearchManually(form) {
    form.classList.remove('active');
    const toggle = form.closest('.search-container-nav')?.querySelector('.search-toggle');
    toggle?.classList.remove('active');
    toggle?.setAttribute('aria-expanded', 'false');
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

    this.removeInputListener('input', this.inputHandler);
    this.removeInputListener('keydown', this.keydownHandler);
    this.removeInputListener('blur', this.blurHandler);

    if (this.mountMode === 'portal') {
      window.removeEventListener('resize', this.visiblePositionUpdateHandler);
      window.removeEventListener('scroll', this.visiblePositionUpdateHandler, true);
    }

    this.suggestionsElement?.remove();
    this.suggestionsElement = null;
    this.input = null;
    this.currentSuggestions = [];
  }

  removeInputListener(event, handler) {
    if (this.input && handler) {
      this.input.removeEventListener(event, handler);
    }
  }
}
