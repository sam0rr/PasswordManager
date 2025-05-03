# SSL Certificate Setup for Local Development

This guide explains how to set up SSL certificates for local development with this project using **mkcert** to generate a trusted certificate for `localhost`, `127.0.0.1`, and `::1`.

## Prerequisites

* macOS with Homebrew installed
* Docker and Docker Compose

## Setting Up SSL Certificates

### 1. Install mkcert

```bash
brew install mkcert
brew install nss  # For Firefox support (optional)
mkcert -install
```

> Creates a local Certificate Authority (CA) and installs it in your system (and Firefox) trust stores.

### 2. Generate certificates for localhost

Run this from your project root to place the certificate and key directly into `docker/services/php`:

```bash
mkcert \
  -cert-file docker/services/php/localhost.pem \
  -key-file  docker/services/php/localhost-key.pem \
  localhost 127.0.0.1 ::1
```

This produces:

* `docker/services/php/localhost.pem`       – the certificate
* `docker/services/php/localhost-key.pem`   – the private key

These files are mounted by Docker Compose:

```yaml
volumes:
  - ./docker/services/php/localhost.pem:/etc/ssl/certs/ssl-cert-snakeoil.pem:ro
  - ./docker/services/php/localhost-key.pem:/etc/ssl/private/ssl-cert-snakeoil.key:ro
```

### 3. Launch the project

Rebuild and start the containers so Apache picks up the new certificate:

```bash
docker-compose up -d --build
```

Visit **[https://localhost](https://localhost)**.

## Troubleshooting

* **Name mismatch**: Ensure you requested `localhost`, `127.0.0.1`, and `::1` exactly when running mkcert.
* **Browser cache**: Hard-refresh or clear your cache if you still see warnings.
* **CA issues**: Rerun `mkcert -install` and regenerate the certs.
* **Manual Apache reload** (if necessary):

  ```bash
  docker exec zephyrus_webserver service apache2 reload
  ```

---

