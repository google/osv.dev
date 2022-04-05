import './styles.scss';
import '@github/clipboard-copy-element';
import '@github/time-elements';
import '@material/mwc-circular-progress';
import '@material/mwc-icon';
import '@material/mwc-icon-button';
import '@hotwired/turbo';
import 'spicy-sections/src/SpicySections';
import {TextField as MwcTextField} from '@material/mwc-textfield';
import {LitElement, html, css, unsafeCSS} from 'lit';
import {unsafeHTML} from 'lit/directives/unsafe-html.js';
import hljs from 'highlight.js';
// TODO: raw-loader is deprecated.
import hljsStyles from '!!raw-loader!highlight.js/styles/github-dark.css';

// Submits a form in a way such that Turbo can intercept the event.
// Triggering submit on the form directly would still give a correct resulting
// page, but we want to let Turbo speed up renders as intended.
const submitForm = function(form) {
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

// A wrapper around <mwc-textfield> that adds back native-like enter key form
// submission behavior.
export class MwcTextFieldWithEnter extends MwcTextField {
  constructor() {
    super();
    this.addEventListener('keyup', (e) => {
      if (e.key === 'Enter') {
        submitForm(this.closest('form'));
      }
    });
  }
}
customElements.define('mwc-textfield-with-enter', MwcTextFieldWithEnter);

export class CodeBlock extends LitElement {
  static get styles() {
    return [
      css`${unsafeCSS(hljsStyles)}`,
      css`:host pre {
        font-family: inherit;
        background: #333;
        border-radius: 10px;
        display: block;
        overflow: auto;
        padding: 10px;
      }`];
  }
  render() {
    const highlighted = hljs.highlightAuto(this.innerHTML).value;
    return html`<pre>${unsafeHTML(highlighted)}</pre>`;
  }
}
customElements.define('code-block', CodeBlock);
