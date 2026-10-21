# Deploying Qbix proxy with Apache

## Before and after

Most Apache + PHP deployments use `mod_php` (PHP embedded in Apache) or `mod_proxy_fcgi` to talk to PHP-FPM:

```
Internet → Apache :443 (TLS) → mod_php / php-fpm.sock
```

With Qbix proxy:

```
Internet → Apache :443 (TLS) → qbixproxy :8080 → php-fpm.sock
```

Apache still handles TLS, static files, `.htaccess`, and rewrite rules. Qbix proxy handles structural sanitization of every request before it reaches PHP.

## Step 1: Install Qbix proxy

```bash
# Download the static binary (zero dependencies)
curl -LO https://github.com/Qbix/proxy/releases/latest/download/qbixproxy-linux-x86_64
chmod +x qbixproxy-linux-x86_64
sudo mv qbixproxy-linux-x86_64 /usr/local/bin/qbixproxy
```

Or build from source:

```bash
sudo apt install musl-tools
make static
sudo cp build/qbixproxy-static /usr/local/bin/qbixproxy
```

## Step 2: Create a config file

Create `/etc/qbixproxy/qbixproxy.json`:

```json
{
  "backends": {
    "php": {
      "socket": "/run/php/php-fpm.sock",
      "protocol": "fastcgi",
      "document_root": "/var/www/html",
      "routes": ["/"],
      "constraints": {
        "max_body_bytes": 8388608,
        "allowed_methods": ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"],
        "allowed_content_types": [
          "application/x-www-form-urlencoded",
          "multipart/form-data",
          "application/json",
          "text/plain"
        ],
        "upload": {
          "max_files": 20,
          "max_file_bytes": 10485760,
          "allowed_extensions": [".jpg", ".jpeg", ".png", ".gif", ".webp", ".pdf", ".zip"]
        }
      }
    }
  }
}
```

Adjust the `socket` path to match your PHP-FPM pool config.

## Step 3: Create a systemd service

Create `/etc/systemd/system/qbixproxy.service`:

```ini
[Unit]
Description=Qbix proxy structural security proxy for PHP
After=network.target php-fpm.service
Wants=php-fpm.service

[Service]
Type=simple
ExecStart=/usr/local/bin/qbixproxy --config=/etc/qbixproxy/qbixproxy.json --port=8080 --host=127.0.0.1
Restart=always
RestartSec=2
User=www-data
Group=www-data

# Hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadOnlyPaths=/etc/qbixproxy

[Install]
WantedBy=multi-user.target
```

```bash
sudo mkdir -p /etc/qbixproxy
sudo cp qbixproxy.json /etc/qbixproxy/
sudo systemctl daemon-reload
sudo systemctl enable --now qbixproxy
```

## Step 4: Update Apache config

First, enable the required modules:

```bash
sudo a2enmod proxy proxy_http rewrite
sudo systemctl restart apache2
```

**Before** (Apache → PHP-FPM directly via `mod_proxy_fcgi`):

```apache
<VirtualHost *:443>
    ServerName example.com
    DocumentRoot /var/www/html

    SSLEngine on
    SSLCertificateFile /etc/letsencrypt/live/example.com/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/example.com/privkey.pem

    <FilesMatch \.php$>
        SetHandler "proxy:unix:/run/php/php-fpm.sock|fcgi://localhost"
    </FilesMatch>

    <Directory /var/www/html>
        AllowOverride All
        Require all granted
    </Directory>
</VirtualHost>
```

**After** (Apache → Qbix proxy → PHP-FPM):

```apache
<VirtualHost *:443>
    ServerName example.com
    DocumentRoot /var/www/html

    SSLEngine on
    SSLCertificateFile /etc/letsencrypt/live/example.com/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/example.com/privkey.pem

    # Static files are still served directly by Apache
    <LocationMatch "\.(css|js|jpg|jpeg|png|gif|ico|svg|woff2?|ttf|eot|mp4|webm|pdf)$">
        # Served from DocumentRoot, no Qbix proxy
    </LocationMatch>

    # Everything else goes through Qbix proxy for sanitization
    ProxyPreserveHost On
    ProxyPass / http://127.0.0.1:8080/
    ProxyPassReverse / http://127.0.0.1:8080/

    # Pass client IP to Qbix proxy
    RequestHeader set X-Real-IP "%{REMOTE_ADDR}s"
    RequestHeader set X-Forwarded-Proto "https"

    <Directory /var/www/html>
        AllowOverride All
        Require all granted
    </Directory>
</VirtualHost>
```

The key change: the `<FilesMatch \.php$>` handler pointing to PHP-FPM is replaced by `ProxyPass` rules pointing to Qbix proxy. Qbix proxy handles the FastCGI protocol to PHP-FPM.

**If you were using `mod_php`** (PHP embedded in Apache), this is also the time to switch to PHP-FPM. `mod_php` runs PHP inside the Apache process, so there is no place to insert Qbix proxy. The switch to PHP-FPM is independent of Qbix proxy and is recommended regardless — it gives better process isolation and resource management.

```bash
# Switch from mod_php to PHP-FPM
sudo a2dismod php8.2          # or whatever version
sudo apt install php8.2-fpm
sudo systemctl enable --now php8.2-fpm
```

## Step 5: Test and reload

```bash
# Test Qbix proxy config
qbixproxy --config=/etc/qbixproxy/qbixproxy.json -t

# Test Apache config
sudo apachectl configtest

# Reload Apache
sudo systemctl reload apache2
```

## Verify it's working

```bash
curl http://127.0.0.1:8080/Q/health
```

Check that your site still works through Apache. The transition should be transparent to your application — Qbix proxy forwards sanitized requests to PHP-FPM the same way Apache's `mod_proxy_fcgi` did, but with every request structurally validated first.

## Notes for Apache users

**`.htaccess` files still work.** Apache processes `.htaccess` rewrite rules before forwarding to Qbix proxy. Your existing `RewriteRule` directives, `ErrorDocument` settings, and access controls are unchanged.

**`mod_security` is complementary.** If you run `mod_security` (Apache's WAF module), it still runs on inbound requests before they reach Qbix proxy. The two are not redundant: `mod_security` matches known attack signatures, Qbix proxy eliminates entire classes of structural attacks regardless of signature. They work well together.
