#!/usr/bin/env bash
set -euo pipefail

# Color codes
TextGreen='\033[0;32m'
TextBlue='\033[0;34m'
TextYellow='\033[1;33m'
TextRed='\033[0;31m'
TextReset='\033[0m'

# Print an error and exit
error() {
  echo -e "${TextRed}Error:${TextReset} $1" >&2
  exit 1
}

# Run a command, echo it first, abort on failure
run() {
  echo "+ $*"
  "$@" || error "'$*' failed"
}

echo -e "${TextBlue}=== Local Development Environment Setup ===${TextReset}"
echo -e "\n${TextYellow}1/– Checking prerequisites…${TextReset}"

# 1. Ensure core tools are installed
for cmd in docker php node npm; do
  command -v "$cmd" &> /dev/null || error "$cmd is not installed"
done

# 2. Detect Docker Compose (v1 or v2)
if command -v docker-compose &> /dev/null; then
  COMPOSE_CMD=(docker-compose)
elif docker compose version &> /dev/null; then
  COMPOSE_CMD=(docker compose)
else
  error "Docker Compose is not available"
fi

# 3. Default environment variables
: "${WEBSERVER_NAME:=kryptlok_webserver}"
: "${DB_HOSTNAME:=kryptlok_database}"
: "${DB_NAME:=kryptlok}"
: "${DB_USERNAME:=postgres}"
: "${DB_PASSWORD:=postgres}"

echo -e "${TextYellow}Using configuration:${TextReset}"
echo -e "  • Webserver: $WEBSERVER_NAME"
echo -e "  • Database : $DB_HOSTNAME"

# 4. Install Composer if missing
echo -e "\n${TextYellow}2/– Composer setup…${TextReset}"
if ! command -v composer &> /dev/null; then
  echo -e "${TextYellow}Installing composer…${TextReset}"
  run php -r "copy('https://getcomposer.org/installer','composer-setup.php')"

  # fetch expected signature via wget or curl
  if command -v wget &> /dev/null; then
    EXPECTED_SIG="$(wget -q -O - https://composer.github.io/installer.sig)"
  elif command -v curl &> /dev/null; then
    EXPECTED_SIG="$(curl -s https://composer.github.io/installer.sig)"
  else
    error "Neither wget nor curl is installed; one is required to verify Composer signature"
  fi
  ACTUAL_SIG="$(php -r "echo hash_file('sha384','composer-setup.php');")"
  [ "$EXPECTED_SIG" == "$ACTUAL_SIG" ] || error "Invalid composer installer signature"

  run php composer-setup.php --quiet
  rm composer-setup.php
  if command -v sudo &> /dev/null; then
    run sudo mv composer.phar /usr/local/bin/composer
  else
    echo -e "${TextYellow}Composer installed locally. Move composer.phar into PATH if needed.${TextReset}"
  fi
fi
COMPOSER_CMD=( "$(command -v composer || echo "./composer.phar")" )

# 5. Install mkcert on macOS if missing
echo -e "\n${TextYellow}3/– mkcert setup…${TextReset}"
if ! command -v mkcert &> /dev/null; then
  echo -e "${TextYellow}Installing mkcert (macOS)…${TextReset}"
  [[ "$OSTYPE" == darwin* ]] || error "mkcert must be installed manually on non-macOS"
  command -v brew &> /dev/null || error "Homebrew required for mkcert"
  run brew install mkcert nss
fi

# 6. Generate and install local CA
echo -e "\n${TextGreen}Step 1: Installing mkcert CA…${TextReset}"
run mkcert -install

# 7. Create SSL certificates
echo -e "\n${TextGreen}Step 2: Generating SSL certificates…${TextReset}"
run mkdir -p docker/services/php
run mkcert \
  -cert-file docker/services/php/localhost.pem \
  -key-file  docker/services/php/localhost-key.pem \
  localhost 127.0.0.1 ::1
run chmod 600 docker/services/php/localhost-key.pem

echo -e "${TextGreen}Certificates created:${TextReset}"
echo -e "  • docker/services/php/localhost.pem"
echo -e "  • docker/services/php/localhost-key.pem"

# 8. PHP dependencies (ignore missing ssh2/apcu)
echo -e "\n${TextGreen}Step 3: Installing PHP dependencies…${TextReset}"
if [ -f composer.json ]; then
  run "${COMPOSER_CMD[@]}" install \
    --ignore-platform-req=ext-ssh2 \
    --ignore-platform-req=ext-apcu
else
  echo -e "${TextYellow}composer.json not found, skipping PHP install${TextReset}"
fi

# 9. NPM dependencies
echo -e "\n${TextGreen}Step 4: Installing NPM dependencies…${TextReset}"
run npm install

# 10. Service worker
echo -e "\n${TextGreen}Step 5: Generating service worker…${TextReset}"
run npm run generate-sw

# 11. Docker containers
echo -e "\n${TextGreen}Step 6: Starting Docker containers…${TextReset}"
# force recreate et remove orphans
run "${COMPOSE_CMD[@]}" up -d --build --force-recreate --remove-orphans

# 12. Composer in container (ignore missing extensions)
echo -e "\n${TextGreen}Step 7: Installing composer in container…${TextReset}"
if [ ! -d vendor ]; then
  if docker exec "$WEBSERVER_NAME" composer install --no-interaction \
      --ignore-platform-req=ext-ssh2 \
      --ignore-platform-req=ext-apcu; then
    echo -e "${TextGreen}Composer installed in container${TextReset}"
  else
    echo -e "${TextYellow}Fallback: creating vendor dir and retrying…${TextReset}"
    run docker exec "$WEBSERVER_NAME" bash -c '[ -d /var/www/html/vendor ] || mkdir -p /var/www/html/vendor'
    run docker exec "$WEBSERVER_NAME" bash -c \
      'cd /var/www/html && composer install --no-interaction \
        --ignore-platform-req=ext-ssh2 \
        --ignore-platform-req=ext-apcu'
  fi
else
  echo -e "${TextYellow}vendor/ exists, skipping container install${TextReset}"
fi

# 13. Clear Latte cache
echo -e "\n${TextGreen}Step 8: Clearing Latte cache…${TextReset}"
run docker exec "$WEBSERVER_NAME" composer latte-cache

echo -e "\n${TextGreen}=== Setup completed successfully ===${TextReset}"

echo -e "\n${TextYellow}🔗  Your app is now available at:${TextReset} https://localhost/login\n"

echo -e "\n${TextYellow}Tips:${TextReset}"
echo -e "- Clear cache or hard refresh if changes don't show"
echo -e "- Run: npm run generate-sw after asset changes"

