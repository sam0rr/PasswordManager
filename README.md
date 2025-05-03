# Local Development Setup Guide

This guide explains how to set up SSL certificates for local development and configure the Workbox service worker for offline capabilities.

## SSL Certificate Setup

### Prerequisites

* macOS with Homebrew installed
* Docker and Docker Compose

### Setting Up SSL Certificates

#### 1. Install mkcert

```bash
brew install mkcert
brew install nss  # For Firefox support (optional)
mkcert -install
```

This creates a local Certificate Authority (CA) and installs it in your system (and Firefox) trust stores.

#### 2. Generate certificates for localhost

Run this from your project root to place the certificate and key directly into docker/services/php:

```bash
mkcert \
  -cert-file docker/services/php/localhost.pem \
  -key-file docker/services/php/localhost-key.pem \
  localhost 127.0.0.1 ::1
```

This produces:
- `docker/services/php/localhost.pem` – the certificate
- `docker/services/php/localhost-key.pem` – the private key

These files are mounted by Docker Compose:

```yaml
volumes:
  - ./docker/services/php/localhost.pem:/etc/ssl/certs/ssl-cert-snakeoil.pem:ro
  - ./docker/services/php/localhost-key.pem:/etc/ssl/private/ssl-cert-snakeoil.key:ro
```

## Workbox Service Worker Setup

### Prerequisites

* Node.js and npm installed

### Setting Up Workbox

#### 1. Install dependencies

```bash
npm install
```

Installs the required dependencies including workbox-cli from package.json

#### 2. Generate the service worker

Run this from your project root to generate the service worker based on the configuration:

```bash
npx workbox generateSW workbox-config.js
```

This creates:
- `public/serviceWorker.js` – the generated service worker file

The configuration specifies:

```js
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
```

## Launch the Project

After setting up both SSL certificates and the Workbox service worker, you can now launch the project:

#### 1. Build and start the containers

```bash
docker-compose up -d --build
```

#### 2. Access the project

Visit `https://localhost`.

## Troubleshooting

- **Name mismatch**: Ensure you requested localhost, 127.0.0.1, and ::1 exactly when running mkcert.
- **Browser cache**: Hard-refresh or clear your cache if you still see warnings.
- **CA issues**: Rerun `mkcert -install` and regenerate the certs.
- **Manual Apache reload** (if necessary):
  ```bash
  docker exec zephyrus_webserver service apache2 reload
  ```
- **Service worker not working**: Check browser console for errors and verify the service worker is registered correctly.