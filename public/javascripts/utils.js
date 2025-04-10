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

document.addEventListener('DOMContentLoaded', function () {
    const avatarInput = document.getElementById('avatar-input');
    const preview = document.getElementById('avatar-preview');

    if (avatarInput) {
        avatarInput.addEventListener('change', function (event) {
            const file = event.target.files[0];
            if (file) {
                const reader = new FileReader();
                reader.onload = function (e) {
                    preview.src = e.target.result;
                };
                reader.readAsDataURL(file);
            }
        });
    }
});