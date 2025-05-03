import { bindFormFieldEvents } from './formField.js';
import { bindSelectNavigation, bindAvatarPreview } from './utils.js';
import { serviceWorker } from './font/fontCacheService.js';

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
            serviceWorker.register()
                .then(() => console.log('Service Worker Ready To Cache Fonts'))
                .catch(error => console.error('Service Worker Issue:', error));
        });
    }
}