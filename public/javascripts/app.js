import { bindFormFieldEvents } from './formField.js';
import { bindSelectNavigation, bindAvatarPreview } from './utils.js';

export default class Application {
    #configurations;

    constructor(configurations) {
        this.#configurations = configurations;
    }

    initialize() {
        this.#enableTooltips();
        this.#bindUtilities();
    }

    #enableTooltips() {
        const tooltipTriggerList = document.querySelectorAll('[data-bs-toggle="tooltip"]');
        [...tooltipTriggerList].map(el => new bootstrap.Tooltip(el));
    }

    #bindUtilities() {
        bindFormFieldEvents();
        bindSelectNavigation();
        bindAvatarPreview();
    }
}
