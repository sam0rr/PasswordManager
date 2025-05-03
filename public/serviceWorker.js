const fontCacheService = {
    CACHE_NAME: 'font-cache-v1',

    CACHE_ASSETS: [
        '/fonts/PTSerif/PTSerifCaption-Regular.woff2'
    ],

    async initCache() {
        const cache = await caches.open(this.CACHE_NAME);
        console.log('Font Cache Opened');
        return cache.addAll(this.CACHE_ASSETS);
    },

    async clearOldCaches() {
        const cacheNames = await caches.keys();
        const deletionPromises = cacheNames
            .filter(cacheName => cacheName !== this.CACHE_NAME)
            .map(cacheName => {
                console.log(`Removing Old Cache: ${cacheName}`);
                return caches.delete(cacheName);
            });

        return Promise.all(deletionPromises);
    },

    isFontRequest(url) {
        return url.match(/\.(woff|woff2|ttf|eot)$/);
    },

    async handleFontRequest(request) {
        const cachedResponse = await caches.match(request);
        if (cachedResponse) {
            return cachedResponse;
        }

        try {
            const networkResponse = await fetch(request);

            if (!networkResponse || networkResponse.status !== 200 || networkResponse.type !== 'basic') {
                return networkResponse;
            }

            const responseToCache = networkResponse.clone();
            const cache = await caches.open(this.CACHE_NAME);
            await cache.put(request, responseToCache);

            return networkResponse;
        } catch (error) {
            console.error('Error Retrieving Font:', error);
            return caches.match(request);
        }
    }
};

self.addEventListener('install', (event) => {
    event.waitUntil(
        fontCacheService.initCache()
            .then(() => self.skipWaiting())
    );
});

self.addEventListener('activate', (event) => {
    event.waitUntil(
        fontCacheService.clearOldCaches()
            .then(() => self.clients.claim())
    );
});

self.addEventListener('fetch', (event) => {
    if (fontCacheService.isFontRequest(event.request.url)) {
        event.respondWith(fontCacheService.handleFontRequest(event.request));
    } else {
        event.respondWith(
            fetch(event.request).catch(() => caches.match(event.request))
        );
    }
});