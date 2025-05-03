#!/usr/bin/env bash
set -euo pipefail

cd /var/www/html

if [ -f workbox-config.js ]; then
    CHECKSUM_FILE=".workbox-checksum"
    CURRENT_HASH=$(
        find public -type f \
            \( -name "*.js" -o -name "*.css" -o -name "*.woff2" -o -name "*.ttf" -o -name "*.eot" \) \
            -exec sha1sum {} \; \
        | sha1sum
    )

    if [ ! -f "$CHECKSUM_FILE" ] || [ "$CURRENT_HASH" != "$(cat "$CHECKSUM_FILE")" ]; then
        echo "Changes detected, regenerating serviceWorker.js..."
        workbox generateSW workbox-config.js
        echo "$CURRENT_HASH" > "$CHECKSUM_FILE"
    else
        echo "No changes detected. Skipping Workbox generation."
    fi
fi

a2enmod ssl headers proxy proxy_http
a2dissite default-ssl 2>/dev/null || true
a2ensite custom-ssl

mailcatcher --ip=0.0.0.0 --http-ip=0.0.0.0 &

exec apache2ctl -D FOREGROUND
