# Local Development Setup Guide

This guide explains how to set up your local development environment with SSL certificates and Workbox service worker for offline support.

## Quick Start (Recommended)

We provide an automated setup script that handles everything for you:

```bash
# Make the script executable
chmod +x setup.sh

# Run the setup script
./setup.sh
```

The setup script:
1. Checks for required dependencies
2. Installs mkcert if needed
3. Generates SSL certificates
4. Installs npm dependencies
5. Generates the service worker
6. Builds and starts Docker containers

This is the recommended approach for most developers.

## Manual Setup

If you prefer to set up everything manually, follow these steps:

### Prerequisites
- macOS with Homebrew installed
- Docker and Docker Compose
- Node.js (>=14) and npm

### Step 1: SSL Certificate Setup

```bash
# Install mkcert
brew install mkcert
brew install nss   # Optional, for Firefox support
mkcert -install

# Generate SSL certificates for localhost
mkdir -p docker/services/php
mkcert \
  -cert-file docker/services/php/localhost.pem \
  -key-file docker/services/php/localhost-key.pem \
  localhost 127.0.0.1 ::1
```

This creates:
- `docker/services/php/localhost.pem` — SSL certificate
- `docker/services/php/localhost-key.pem` — SSL private key

These certificates are mounted in the Docker container via docker-compose.yml:
```yaml
volumes:
  - ./docker/services/php/localhost.pem:/etc/ssl/certs/ssl-cert-snakeoil.pem:ro
  - ./docker/services/php/localhost-key.pem:/etc/ssl/private/ssl-cert-snakeoil.key:ro
```

### Step 2: Service Worker Setup

```bash
# Install npm dependencies
npm install

# Generate the service worker
npm run generate-sw
```

This will create:
- `public/serviceWorker.js`
- `public/workbox-*.js`
- Their source-maps

The `generate-sw` script defined in package.json calls Workbox CLI:
```json
{
  "scripts": {
    "generate-sw": "workbox generateSW workbox-config.js"
  }
}
```

### Step 3: Start Docker Containers

```bash
# Build and start containers
docker-compose up -d --build
```

## Day-to-Day Development

When your public assets change, you need to regenerate the service worker:

```bash
npm run generate-sw
```

When your html (latte) assets change, you need to regenerate the service worker:
```bash
docker exec -it zephyrus_webserver composer latte-cache
```

Access your local environment at:
```
https://localhost
```

## How It Works

### SSL Certificates

The mkcert tool creates a local certificate authority (CA) trusted by your system. This eliminates browser security warnings while still using HTTPS locally.

### Service Worker Generation

Workbox CLI reads your `workbox-config.js` configuration and automatically generates a service worker that caches your assets for offline use. The service worker needs to be regenerated whenever your assets change.

> **Note:** We keep Node.js out of the Docker container to maintain a lean production-like environment. Service worker generation happens on your local machine before container startup.

## Troubleshooting

- **Certificate not trusted**: Run `mkcert -install` again and regenerate certificates
- **Browser cache issues**: Perform a hard refresh (Ctrl+F5 or Cmd+Shift+R)
- **Service worker errors**: Check the browser console (F12 → Application → Service Workers)
- **Apache issues**: Force reload with `docker exec zephyrus_webserver service apache2 reload`