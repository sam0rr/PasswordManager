#!/usr/bin/env bash
set -euo pipefail

a2enmod ssl headers proxy proxy_http

a2dissite default-ssl 2>/dev/null || true
a2ensite custom-ssl

mailcatcher --ip=0.0.0.0 --http-ip=0.0.0.0 &

exec apache2ctl -D FOREGROUND
