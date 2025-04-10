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

function togglePasswordVisibility(inputId, button) {
    const input = document.getElementById(inputId);
    const icon = button.querySelector('i');

    if (input) {
        // Change l'attribut type au lieu de la propriété
        if (input.getAttribute('type') === 'password') {
            input.setAttribute('type', 'text');
            icon.classList.replace('fa-eye', 'fa-eye-slash');
        } else {
            input.setAttribute('type', 'password');
            icon.classList.replace('fa-eye-slash', 'fa-eye');
        }
    }
}