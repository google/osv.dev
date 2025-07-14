import './styles.scss';
import '@github/clipboard-copy-element';
import '@material/web/icon/icon.js';
import '@material/web/iconbutton/icon-button.js';
import '@material/web/progress/circular-progress.js';
import '@hotwired/turbo';
import 'spicy-sections/src/SpicySections';
import { MdFilledTextField } from '@material/web/textfield/filled-text-field.js';
import { LitElement, html } from 'lit';
import { ExpandableSearch, SearchSuggestionsManager } from './search.js';

// Submits a form in a way such that Turbo can intercept the event.
// Triggering submit on the form directly would still give a correct resulting
// page, but we want to let Turbo speed up renders as intended.
export const submitForm = function (form) {
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
  searchInstance = new ExpandableSearch();
}

// Ensure initialization happens after all dependencies are loaded
function ensureInitialization() {
  if (typeof customElements !== 'undefined' && customElements.get('md-filled-text-field')) {
    initializeSearch();
  } else {
    // wait a bit longer for components to load
    setTimeout(ensureInitialization, 50);
  }
}

if (document.readyState === 'complete') {
  // Page is fully loaded, initialize immediately
  setTimeout(ensureInitialization, 0);
} else if (document.readyState === 'interactive') {
  // DOM is ready but resources might still be loading
  setTimeout(ensureInitialization, 100);
} else {
  // DOM is not ready yet
  document.addEventListener('DOMContentLoaded', () => {
    setTimeout(ensureInitialization, 0);
  });
}

// Handle Turbo navigation
document.addEventListener('turbo:load', () => {
  setTimeout(ensureInitialization, 0);
});

// Fallback
window.addEventListener('load', () => {
  if (!searchInstance) {
    setTimeout(ensureInitialization, 0);
  }
});

// Enhanced text field with search suggestions (extends existing MdTextFieldWithEnter)
export class MdTextFieldWithSuggestions extends MdTextFieldWithEnter {
  constructor() {
    super();
    this.suggestionsManager = null;
    this.initializationRetries = 0;
    this.maxRetries = 10;
  }

  connectedCallback() {
    super.connectedCallback();
    // Delay initialization to ensure the element is fully rendered
    this.initializeSuggestions();
  }

  initializeSuggestions() {
    // Don't initialize if already destroyed/disconnected
    if (!this.isConnected) {
      return;
    }
    
    // Wait for the element to be fully rendered
    if (this.offsetHeight === 0 && this.initializationRetries < this.maxRetries) {
      this.initializationRetries++;
      setTimeout(() => this.initializeSuggestions(), 50);
      return;
    }
    
    try {
      if (!this.suggestionsManager && this.isConnected) {
        this.suggestionsManager = new SearchSuggestionsManager(this);
      }
    } catch (error) {
      console.warn('Failed to initialize SearchSuggestionsManager:', error);
      // Retry initialization after a delay
      if (this.initializationRetries < this.maxRetries && this.isConnected) {
        this.initializationRetries++;
        setTimeout(() => this.initializeSuggestions(), 100);
      }
    }
  }

  disconnectedCallback() {
    super.disconnectedCallback();
    if (this.suggestionsManager) {
      this.suggestionsManager.destroy();
      this.suggestionsManager = null;
    }
  }
}
customElements.define('md-textfield-with-suggestions', MdTextFieldWithSuggestions);
