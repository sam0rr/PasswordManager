export function bindFormFieldToggle(fieldId) {
    const button = document.querySelector('[data-password-toggle="' + fieldId + '"]');
    const input = document.getElementById(fieldId);
    if (!button || !input || button.dataset.bound === "true") return;

    button.dataset.bound = "true";

    const icon = button.querySelector("i");

    const toggleKey = button.getAttribute("data-toggle-key") || input.name || fieldId;
    const storageKey = "password-toggle-" + toggleKey;

    const saved = sessionStorage.getItem(storageKey);
    if (saved === "visible") {
        input.type = "text";
        if (icon) icon.classList.replace("fa-eye", "fa-eye-slash");
    }

    button.addEventListener("click", () => {
        const isHidden = input.type === "password";
        input.type = isHidden ? "text" : "password";
        if (icon) icon.classList.replace(
            isHidden ? "fa-eye" : "fa-eye-slash",
            isHidden ? "fa-eye-slash" : "fa-eye"
        );
        sessionStorage.setItem(storageKey, isHidden ? "visible" : "hidden");
    });
}

export function bindAllFormFieldToggles() {
    document.querySelectorAll('[data-password-toggle]').forEach(button => {
        const fieldId = button.getAttribute("data-password-toggle");
        if (fieldId) {
            bindFormFieldToggle(fieldId);
        }
    });
}

export function bindFormFieldEvents() {
    document.addEventListener("DOMContentLoaded", bindAllFormFieldToggles);
    document.addEventListener("htmx:afterSwap", bindAllFormFieldToggles);
}
