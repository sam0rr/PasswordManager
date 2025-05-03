import { fontCacheService } from '/javascripts/font/fontCacheService.js';

self.addEventListener('install', event => {
    event.waitUntil(
        fontCacheService
            .init()
            .then(() => self.skipWaiting())
    );
});

self.addEventListener('activate', event => {
    event.waitUntil(
        fontCacheService
            .cleanup()
            .then(() => self.clients.claim())
    );
});

async function networkFirst(request) {
    try {
        return await fetch(request);
    } catch {
        return caches.match(request);
    }
}

self.addEventListener('fetch', event => {
    const { request } = event;

    if (fontCacheService.isFontRequest(request)) {
        event.respondWith(fontCacheService.fetchAndCache(request));
    } else {
        event.respondWith(networkFirst(request));
    }
});
