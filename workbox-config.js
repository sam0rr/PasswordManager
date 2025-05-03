require('dotenv').config();

const FONT_TTL = parseInt(
    process.env.CACHE_MAX_AGE_SECONDS,
    10
) || 60 * 60 * 24 * 365 * 2;

module.exports = {
    globDirectory: 'public',
    globPatterns: [
        '**/*.{html,js,css,woff2,ttf,eot}'
    ],
    swDest: 'public/serviceWorker.js',
    runtimeCaching: [
        {
            urlPattern: /\.(?:woff2?|ttf|eot)$/i,
            handler: 'CacheFirst',
            options: {
                cacheName: 'font-cache-v1',
                expiration: {
                    maxEntries: 20,
                    maxAgeSeconds: FONT_TTL,
                },
            },
        },
        {
            urlPattern: /\/.*/i,
            handler: 'NetworkFirst',
            options: {
                cacheName: 'runtime-cache',
            },
        },
    ],
};
