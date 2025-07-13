export class ExpandableSearch {
  constructor() {
    this.containers = [];
    
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
    
    searchToggle.removeEventListener('click', toggleHandler);
    searchToggle.addEventListener('click', toggleHandler);
    searchToggle.setAttribute('data-search-initialized', 'true');

    const submitHandler = (e) => {
      const query = searchInput.value.trim();
      if (!query) {
        e.preventDefault();
      }
    };
    
    searchForm.removeEventListener('submit', submitHandler);
    searchForm.addEventListener('submit', submitHandler);
    searchForm.setAttribute('data-search-initialized', 'true');
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
  }
}
