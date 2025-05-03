const CACHE_NAME = 'font-cache-v1';
const FONT_ASSETS = [
    '/fonts/PTSerif/PTSerifCaption-Regular.woff2'
];

export const fontCacheService = {
    async init() {
        const cache = await caches.open(CACHE_NAME);
        await cache.addAll(FONT_ASSETS);
        console.log(`${CACHE_NAME} Initialized`);
    },

    async cleanup() {
        const keys = await caches.keys();
        await Promise.all(
            keys
                .filter(key => key !== CACHE_NAME)
                .map(key => caches.delete(key))
        );
        console.log(`Old Caches Cleared`);
    },

    isFontRequest(request) {
        return /\.(woff2?|ttf|eot)$/i.test(new URL(request.url).pathname);
    },

    async fetchAndCache(request) {
        const cache = await caches.open(CACHE_NAME);
        const cached = await cache.match(request);
        if (cached) {
            return cached;
        }

        try {
            const response = await fetch(request);
            if (response.ok && response.type === 'basic') {
                await cache.put(request, response.clone());
            }
            return response;
        } catch {
            return (await cache.match(request)) || Response.error();
        }
    }
};
