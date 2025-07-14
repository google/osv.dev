import './styles.scss';
import '@github/clipboard-copy-element';
import '@material/web/icon/icon.js';
import '@material/web/iconbutton/icon-button.js';
import '@material/web/progress/circular-progress.js';
import '@hotwired/turbo';
import 'spicy-sections/src/SpicySections';
import { MdFilledTextField } from '@material/web/textfield/filled-text-field.js';
import { LitElement, html } from 'lit';
import { ExpandableSearch } from './search.js';

// Submits a form in a way such that Turbo can intercept the event.
// Triggering submit on the form directly would still give a correct resulting
// page, but we want to let Turbo speed up renders as intended.
const submitForm = function (form) {
  if (!form) {
    return;
  }
  const fakeSubmit = document.createElement('input');
  fakeSubmit.type = 'submit';
  fakeSubmit.style.display = 'none';
  form.appendChild(fakeSubmit);
  fakeSubmit.click();
  fakeSubmit.remove();
}

// A wrapper around <input type=radio> elements that submits their parent form
// when any radio item changes.
export class SubmitRadiosOnClickContainer extends LitElement {
  constructor() {
    super();
    this.addEventListener('change', () => submitForm(this.closest('form')))
  }
  // Render the contents of the element as-is.
  render() { return html`<slot></slot>`; }
}
customElements.define('submit-radios', SubmitRadiosOnClickContainer);

// A wrapper around <md-filled-textfield> that adds back native-like enter key form
// submission behavior.
export class MdTextFieldWithEnter extends MdFilledTextField {
  constructor() {
    super();
    this.addEventListener('keyup', (e) => {
      if (e.key === 'Enter') {
        submitForm(this.closest('form'));
      }
    });
  }
}
customElements.define('md-textfield-with-enter', MdTextFieldWithEnter);

let searchInstance = null;

function initializeSearch() {
  // Clean up previous instance if it exists
  searchInstance = new ExpandableSearch();
}

if (document.readyState === 'complete' || document.readyState === 'interactive') {
  setTimeout(initializeSearch, 0);
}

document.addEventListener('DOMContentLoaded', () => {
  initializeSearch();
});

document.addEventListener('turbo:load', () => {
  initializeSearch();
});

window.addEventListener('load', () => {
  if (!searchInstance) {
    initializeSearch();
  }
});

// ============= SEARCH SUGGESTIONS =============

// search suggestions manager for vulnerability search
class SearchSuggestionsManager {
  constructor(inputElement) {
    this.input = inputElement;
    this.suggestionsElement = null;
    this.selectedIndex = -1;
    this.currentSuggestions = [];
    this.debounceTimer = null;
    
    this.init();
  }

  init() {
    this.createSuggestionsElement();
    this.setupEventListeners();
  }

  createSuggestionsElement() {
    this.suggestionsElement = document.createElement('div');
    this.suggestionsElement.classList.add('search-suggestions');
    this.suggestionsElement.style.display = 'none';
    document.body.appendChild(this.suggestionsElement);
  }

  setupEventListeners() {
    this.input.addEventListener('input', () => {
      this.selectedIndex = -1;
      clearTimeout(this.debounceTimer);
      this.debounceTimer = setTimeout(() => this.handleInput(), 300);
    });

    this.input.addEventListener('keydown', (e) => this.handleKeydown(e));
    this.input.addEventListener('blur', () => setTimeout(() => this.hide(), 200));
  }

  async handleInput() {
    const query = this.input.value.trim();
    
    if (query.length < 2) {
      this.hide();
      return;
    }
    
    try {
      const response = await fetch(`/api/search_suggestions?q=${encodeURIComponent(query)}`);
      const data = await response.json();
      this.currentSuggestions = data.suggestions || [];
      this.show();
    } catch (error) {
      console.error('Error fetching suggestions:', error);
      this.hide();
    }
  }

  handleKeydown(e) {
    if (!this.suggestionsElement || this.suggestionsElement.style.display === 'none') return;

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
    this.suggestionsElement.style.left = `${rect.left}px`;
    this.suggestionsElement.style.top = `${rect.bottom}px`;
    this.suggestionsElement.style.width = `${rect.width}px`;
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
    clearTimeout(this.debounceTimer);
    if (this.suggestionsElement) {
      this.suggestionsElement.remove();
    }
  }
}

// Enhanced text field with search suggestions (extends existing MdTextFieldWithEnter)
export class MdTextFieldWithSuggestions extends MdTextFieldWithEnter {
  constructor() {
    super();
    this.suggestionsManager = null;
  }

  connectedCallback() {
    super.connectedCallback();
    this.suggestionsManager = new SearchSuggestionsManager(this);
  }

  disconnectedCallback() {
    super.disconnectedCallback();
    if (this.suggestionsManager) {
      this.suggestionsManager.destroy();
    }
  }
}
customElements.define('md-textfield-with-suggestions', MdTextFieldWithSuggestions);
