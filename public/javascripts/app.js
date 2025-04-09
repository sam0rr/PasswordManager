export default class Application {

    #configurations;

    constructor(configurations) {
        this.#configurations = configurations;
    }

    initialize() {
        this.#enableTooltips();
    }

    #enableTooltips() {
        const tooltipTriggerList = document.querySelectorAll('[data-bs-toggle="tooltip"]')
        const tooltipList = [...tooltipTriggerList].map(tooltipTriggerEl => new bootstrap.Tooltip(tooltipTriggerEl))
    }
}

document.addEventListener("DOMContentLoaded", () => {
    document.querySelectorAll("select").forEach((selector) => {
        selector.addEventListener("change", function () {
            const url = this.value;
            if (url && url.startsWith("?")) {
                window.location.href = window.location.pathname + url;
            } else {
                window.location.href = url;
            }
        });
    });
});


