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
  if (searchInstance) {
    // Previous instance will be cleaned up by the new instance
  }
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

