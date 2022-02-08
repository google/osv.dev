import './styles.scss';
import '@material/mwc-circular-progress';
import '@material/mwc-icon';
import '@material/mwc-icon-button';
import '@hotwired/turbo';
import 'spicy-sections/src/SpicySections';
import {TextField as MwcTextField} from '@material/mwc-textfield';

import {MDCDataTable} from '@material/data-table';
const dataTable = new MDCDataTable(document.querySelector('.mdc-data-table'));
console.log('dataTable', dataTable);

// A wrapper around <mwc-textfield> that adds back native-like enter key form
// submission behavior.
export class MwcTextFieldWithEnter extends MwcTextField {
  constructor() {
    super();
    this.addEventListener('keyup', (e) => {
      if (e.key !== 'Enter') {
        return;
      }
      const form = this.closest('form');
      if (form) {
        e.preventDefault();
        // Make a fake input and submit it. If the actual form is submitted,
        // Turbo won't intercept the event.
        const fakeSubmit = document.createElement('input');
        fakeSubmit.type = 'submit';
        fakeSubmit.style.display = 'none';
        form.appendChild(fakeSubmit);
        fakeSubmit.click();
        fakeSubmit.remove();
      }
    });
  }
}
customElements.define('mwc-textfield-with-enter', MwcTextFieldWithEnter);
