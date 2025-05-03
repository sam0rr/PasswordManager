# Local Development Setup Guide

This guide explains how to set up SSL certificates for local development and how the Workbox service worker is automatically generated and used for offline support.

## SSL Certificate Setup

### Prerequisites
- macOS with Homebrew installed
- Docker and Docker Compose

### Steps

1. **Install mkcert**
   ```bash
   brew install mkcert
   brew install nss   # Optional, for Firefox support
   mkcert -install
   ```
   This installs a local Certificate Authority (CA) and trusts it in your system and browser stores.

2. **Generate SSL certificates for localhost**
   From the root of your project, run:
   ```bash
   mkcert \
     -cert-file docker/services/php/localhost.pem \
     -key-file  docker/services/php/localhost-key.pem \
     localhost 127.0.0.1 ::1
   ```
   This creates:
   - `docker/services/php/localhost.pem` — SSL certificate
   - `docker/services/php/localhost-key.pem` — SSL private key

   These files are mounted in Docker via docker-compose.yml:
   ```yaml
   volumes:
     - ./docker/services/php/localhost.pem:/etc/ssl/certs/ssl-cert-snakeoil.pem:ro
     - ./docker/services/php/localhost-key.pem:/etc/ssl/private/ssl-cert-snakeoil.key:ro
   ```

## Workbox Service Worker Setup

### Prerequisites
- Node.js (>=14) and npm

### Steps

1. **Install JavaScript dependencies**
   ```bash
   npm install
   ```
   This installs your devDependencies (including workbox-cli).

   If you ever want to check for vulnerabilities or upgrade, you can run:
   ```bash
   npm audit
   ```

2. **There is an helper script in package.json**
   In your "scripts" section:
   ```json
   {
     "scripts": {
       "generate-sw": "workbox generateSW workbox-config.js"
     }
   }
   ```
   This lets you regenerate your service worker on demand.

3. **Generate service worker before first run**
   ```bash
   npm run generate-sw
   ```
   This will write:
   - `public/serviceWorker.js`
   - `public/workbox-*.js`
   - Their source-maps

4. **Manual regeneration**
   If you've added or removed assets, you need to manually re-run:
   ```bash
   npm run generate-sw
   ```

## Starting the Project

### Option 1: Automated Setup (Recommended)

We've included a setup script that automates all the installation steps:

```bash
# Make the script executable
chmod +x setup.sh

# Run the setup script
./setup.sh
```

The script will:
1. Check for required dependencies
2. Install and configure mkcert
3. Generate SSL certificates
4. Install npm dependencies
5. Generate the service worker
6. Build and start the Docker containers

### Option 2: Manual Setup

If you prefer to run the commands manually, follow this sequence:

```bash
npm install
npm run generate-sw
docker-compose up -d --build
```

### After Setup

When your assets change:
```bash
npm run generate-sw
```

Open your browser at:
```
https://localhost
```

## Troubleshooting

- **Certificate not trusted**: re-run `mkcert -install` and regenerate certs.
- **Browser cache issues**: perform a hard refresh or clear cache.
- **Service worker errors**: inspect the browser console and Application → Service Workers pane.
- **Force Apache reload** (if needed):
  ```bash
  docker exec zephyrus_webserver service apache2 reload
  ```