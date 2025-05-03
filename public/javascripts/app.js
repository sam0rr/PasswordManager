import { bindFormFieldEvents } from './formField.js';
import { bindSelectNavigation, bindAvatarPreview } from './utils.js';
import { registerServiceWorker } from './serviceWorkerRegistration.js';

export default class Application {
    #configurations;

    constructor(configurations) {
        this.#configurations = configurations;
    }

    initialize() {
        this.#enableTooltips();
        this.#bindUtilities();
        this.#registerServiceWorker();
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

    #registerServiceWorker() {
        window.addEventListener('load', () => {
            registerServiceWorker()
                .then(reg => {
                    console.log('Service Worker Ready To Cache Fonts:', reg.scope);
                })
                .catch(err => {
                    console.error('Service Worker Issue:', err);
                });
        });
    }
}
