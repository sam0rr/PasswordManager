export async function registerServiceWorker() {
    if (!('serviceWorker' in navigator)) return;
    try {
        const registration = await navigator.serviceWorker.register(
            '/serviceWorker.js',
            { type: 'module' }
        );
        console.log('SW registered:', registration.scope);
        return registration;
    } catch (err) {
        console.error('SW registration failed:', err);
    }
}

