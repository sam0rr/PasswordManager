const PASSWORD_TOGGLE_EXPIRATION_MINUTES = 5;

export function bindFormFieldToggle(fieldId) {
    const button = document.querySelector(`[data-password-toggle="${fieldId}"]`);
    const input = document.getElementById(fieldId);
    if (!button || !input || button.dataset.bound === "true") return;

    button.dataset.bound = "true";

    const icon = button.querySelector("i");
    const storageKey = _getStorageKey(button, input, fieldId);

    _restorePasswordState(input, icon, storageKey);
    button.addEventListener("click", () => _togglePasswordVisibility(input, icon, storageKey));
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

function _getStorageKey(button, input, fallback) {
    const toggleKey = button.getAttribute("data-toggle-key") || input.name || fallback;
    return `password-toggle-${toggleKey}`;
}

function _restorePasswordState(input, icon, storageKey) {
    const saved = JSON.parse(sessionStorage.getItem(storageKey) || "{}");
    const maxAgeMs = PASSWORD_TOGGLE_EXPIRATION_MINUTES * 60 * 1000;

    if (saved.state === "visible" && (Date.now() - saved.timestamp) < maxAgeMs) {
        input.type = "text";
        icon?.classList.replace("fa-eye", "fa-eye-slash");
    } else {
        sessionStorage.removeItem(storageKey);
    }
}

function _togglePasswordVisibility(input, icon, storageKey) {
    const isHidden = input.type === "password";
    input.type = isHidden ? "text" : "password";
    icon?.classList.replace(
        isHidden ? "fa-eye" : "fa-eye-slash",
        isHidden ? "fa-eye-slash" : "fa-eye"
    );
    sessionStorage.setItem(storageKey, JSON.stringify({
        state: isHidden ? "visible" : "hidden",
        timestamp: Date.now()
    }));
}
