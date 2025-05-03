# SSL Certificate Setup for Local Development

This guide explains how to set up SSL certificates for local development with this project.

## Prerequisites

- macOS with Homebrew installed
- Docker and Docker Compose

## Setting Up SSL Certificates

### 1. Install mkcert

```bash
brew install mkcert
brew install nss  # For Firefox support (optional)
```

### 2. Create a trusted local certificate authority

```bash
mkcert -install
```

### 3. Generate certificates for localhost

```bash
mkcert localhost
```

This will create two files:
- `localhost.pem` (the certificate)
- `localhost-key.pem` (the private key)

### 4. Place these files in the project root directory

Make sure both certificate files are placed in the root directory of the project, alongside the `compose.yaml` file.

## Running the Project

After setting up the certificates, you can start the project with:

```bash
docker-compose up -d
```

The application should now be accessible at `https://localhost` with a valid SSL certificate.

**Note:** If you have issues with the SSL certificate not being recognized, you can manually reload Apache after the containers are running:

```bash
docker exec zephyrus_webserver service apache2 reload
```

However, this should not be necessary in most cases.

## Troubleshooting

If you encounter certificate errors:
- Make sure the certificate files are named exactly `localhost.pem` and `localhost-key.pem`
- Ensure the files are in the project root directory
- Try restarting your browser
- Run `mkcert -install` again if necessary