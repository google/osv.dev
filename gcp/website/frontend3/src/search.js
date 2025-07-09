export class ExpandableSearch {
  constructor() {
    this.containers = [];
    this.debounceTimers = new Map();
    
    this.cleanupExistingInstances();
    
    this.setupGlobalListeners();
    
    this.initializeSearch();
    
    console.debug('ExpandableSearch initialized');
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
      
      if (window.OSVSearchInstance.debounceTimers) {
        window.OSVSearchInstance.debounceTimers.forEach(timer => clearTimeout(timer));
      }
      
      console.debug('Cleaned up previous search instance');
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
      console.debug(`Search container not found: ${containerSelector}`);
      return;
    }

    const searchForm = searchContainer.querySelector('.search-form');
    const searchToggle = searchContainer.querySelector('.search-toggle');
    const searchInput = searchContainer.querySelector('.search-input');
    
    if (!searchForm || !searchToggle || !searchInput) {
      console.debug(`Search elements missing in container: ${containerSelector}`);
      return;
    }

    const suggestionsDropdown = this.createSuggestionsDropdown();
    
    const containerInfo = {
      element: searchContainer,
      form: searchForm,
      toggle: searchToggle,
      input: searchInput,
      suggestions: suggestionsDropdown
    };
    
    this.containers.push(containerInfo);

    searchForm.appendChild(suggestionsDropdown);

    const toggleHandler = (e) => {
      e.preventDefault();
      const isActive = searchForm.classList.contains('active');
      
      if (isActive) {
        this.closeSearch(containerInfo);
      } else {
        this.openSearch(containerInfo);
      }
    };
    
    searchToggle.removeEventListener('click', toggleHandler);
    
    searchToggle.addEventListener('click', toggleHandler);
    
    searchToggle.setAttribute('data-search-initialized', 'true');

    const inputHandler = (e) => {
      if (this.debounceTimers.has(searchInput)) {
        clearTimeout(this.debounceTimers.get(searchInput));
      }
      
      const query = e.target.value.trim();
      
      if (query.length === 0) {
        this.clearSuggestions(suggestionsDropdown);
        return;
      }
      
      const timer = setTimeout(() => {
        this.fetchSuggestions(query, suggestionsDropdown);
      }, 300);
      
      this.debounceTimers.set(searchInput, timer);
    };
    
    searchInput.removeEventListener('input', inputHandler);
    
    searchInput.addEventListener('input', inputHandler);
    
    searchInput.setAttribute('data-search-initialized', 'true');

    const submitHandler = (e) => {
      const query = searchInput.value.trim();
      if (!query) {
        e.preventDefault();
      }
    };
    
    searchForm.removeEventListener('submit', submitHandler);
    
    searchForm.addEventListener('submit', submitHandler);
    
    searchForm.setAttribute('data-search-initialized', 'true');
    
    console.debug(`Initialized search container: ${containerSelector}`);
  }
  
  createSuggestionsDropdown() {
    const dropdown = document.createElement('div');
    dropdown.className = 'search-suggestions';
    dropdown.style.display = 'none';
    return dropdown;
  }
  
  fetchSuggestions(query, dropdown) {
    if (!query) {
      this.clearSuggestions(dropdown);
      return;
    }
    
    dropdown.innerHTML = '<div class="suggestion-item">Loading...</div>';
    dropdown.style.display = 'block';
    
    fetch(`/api/search_suggestions?q=${encodeURIComponent(query)}`)
      .then(response => response.json())
      .then(data => {
        if (data.suggestions && data.suggestions.length > 0) {
          this.displaySuggestions(query, data.suggestions, dropdown);
        } else {
          this.clearSuggestions(dropdown);
        }
      })
      .catch(error => {
        console.error('Error fetching suggestions:', error);
        this.clearSuggestions(dropdown);
      });
  }
  
  displaySuggestions(query, suggestions, dropdown) {
    dropdown.innerHTML = '';
    
    suggestions.forEach(suggestion => {
      const item = document.createElement('div');
      item.className = 'suggestion-item';
      
      const highlightedText = this.highlightMatch(suggestion, query);
      item.innerHTML = highlightedText;
      
      const clickHandler = () => {
        const input = dropdown.closest('.search-form').querySelector('.search-input');
        if (input) {
          input.value = suggestion;
          this.clearSuggestions(dropdown);
          
          const form = dropdown.closest('.search-form');
          if (form) {
            form.dispatchEvent(new Event('submit', { cancelable: true }));
            form.submit();
          }
        }
      };
      
      item.addEventListener('click', clickHandler);
      
      dropdown.appendChild(item);
    });
    
    dropdown.style.display = 'block';
  }
  
  highlightMatch(text, query) {
    const lowerText = text.toLowerCase();
    const lowerQuery = query.toLowerCase();
    const index = lowerText.indexOf(lowerQuery);
    
    if (index !== -1) {
      return text.substring(0, index) +
             '<strong>' + text.substring(index, index + query.length) + '</strong>' +
             text.substring(index + query.length);
    }
    
    // No match found, return original text
    return text;
  }
  
  clearSuggestions(dropdown) {
    if (!dropdown) return;
    dropdown.innerHTML = '';
    dropdown.style.display = 'none';
  }

  openSearch(container) {
    if (!container || !container.form) return;
    
    container.form.classList.add('active');
    container.toggle.classList.add('active');
    container.toggle.setAttribute('aria-expanded', 'true');
    
    setTimeout(() => {
      if (container.input) container.input.focus();
    }, 100);
  }

  closeSearch(container) {
    if (!container || !container.form) return;
    
    container.form.classList.remove('active');
    container.toggle.classList.remove('active');
    container.toggle.setAttribute('aria-expanded', 'false');
    
    if (container.input) container.input.blur();
    
    if (container.suggestions) {
      this.clearSuggestions(container.suggestions);
    }
  }
}
