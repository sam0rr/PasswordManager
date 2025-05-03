// fontCacheService.js
export const fontCacheService = {
    CACHE_NAME: 'font-cache-v1',
    // ... rest of your code
};

export const serviceWorker = {
    async register() {
        if ('serviceWorker' in navigator) {
            try {
                const registration = await navigator.serviceWorker.register('/serviceWorker.js');
                console.log('Service Worker Successfully Registered:', registration.scope);
                return registration;
            } catch (error) {
                console.error('Service Worker Registration Failed:', error);
                throw error;
            }
        } else {
            console.warn('Service Workers Not Supported By This Browser');
        }
    }
};