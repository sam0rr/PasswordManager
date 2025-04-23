export function bindSelectNavigation() {
    document.querySelectorAll("select").forEach(selector => {
        selector.addEventListener("change", function () {
            const url = this.value;
            window.location.href = url.startsWith("?")
                ? window.location.pathname + url
                : url;
        });
    });
}

export function bindAvatarPreview() {
    const avatarInput = document.getElementById('avatar-input');
    const preview = document.getElementById('avatar-preview');
    if (avatarInput && preview) {
        avatarInput.addEventListener('change', (e) => {
            const file = e.target.files?.[0];
            if (file) {
                const reader = new FileReader();
                reader.onload = (e) => preview.src = e.target.result;
                reader.readAsDataURL(file);
            }
        });
    }
}
