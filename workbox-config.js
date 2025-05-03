module.exports = {
    globDirectory: 'public',
    globPatterns: [
        '**/*.{html,js,css,woff2,ttf,eot}'
    ],
    swDest: 'public/serviceWorker.js',
    runtimeCaching: [
        {
            urlPattern: /\/.*/i,
            handler: 'NetworkFirst',
            options: {
                cacheName: 'runtime-cache',
            },
        }
    ]
};
