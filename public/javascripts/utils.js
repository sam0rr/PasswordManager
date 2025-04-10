document.addEventListener("DOMContentLoaded", function () {
    document.querySelectorAll('[data-password-toggle]').forEach(button => {
        button.addEventListener("click", () => {
            const inputId = button.getAttribute("data-password-toggle");
            const input = document.getElementById(inputId);
            const icon = button.querySelector("i");

            if (input.getAttribute("type") === "password") {
                input.setAttribute("type", "text");
                icon.classList.replace("fa-eye", "fa-eye-slash");
            } else {
                input.setAttribute("type", "password");
                icon.classList.replace("fa-eye-slash", "fa-eye");
            }
        });
    });

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
