# Deploying Qbix proxy with nginx

## Before and after

Most PHP deployments have nginx talking directly to PHP-FPM:

```
Internet → nginx :443 (TLS) → php-fpm.sock
```

With Qbix proxy, you insert it between nginx and PHP-FPM:

```
Internet → nginx :443 (TLS) → qbixproxy :8080 → php-fpm.sock
```

nginx still handles TLS, static files, and rate limiting. Qbix proxy handles structural sanitization of every request before it reaches PHP.

## Automated setup (recommended)

The fastest way to configure nginx is the included PHP helper. It detects your PHP-FPM socket and nginx config files automatically, shows you a colored preview of every change it will make, then applies everything — binary download, config patches, systemd unit — with a rollback-safe backup:

```bash
# Download the helper
curl -LO https://raw.githubusercontent.com/Qbix/proxy/main/qbixproxy-setup.php

# Step 1: Preview — reads nothing, writes nothing, no root needed
php qbixproxy-setup.php --server=nginx

# Step 2: Apply
sudo php qbixproxy-setup.php --server=nginx
```

If the nginx config test fails after patching, the helper restores your original config from the `.bak` backup automatically. No reload happens unless the test passes.

Not sure if it's safe to run? **[Ask Claude to review it](https://claude.ai/new?q=I%20want%20to%20protect%20my%20PHP%20server%20from%20CVE-2026-109618%20%28php2shell%29.%20Please%20fetch%20and%20review%20the%20Qbix%20proxy%20setup%20script%20at%20https%3A%2F%2Fraw.githubusercontent.com%2FQbix%2Fproxy%2Fmain%2Fqbixproxy-setup.php%2C%20explain%20what%20it%20does%20step%20by%20step%2C%20and%20walk%20me%20through%20running%20it%20safely%20on%20my%20server.)** or **[Ask ChatGPT](https://chatgpt.com/?q=I%20want%20to%20protect%20my%20PHP%20server%20from%20CVE-2026-109618%20%28php2shell%29.%20Please%20fetch%20and%20review%20the%20Qbix%20proxy%20setup%20script%20at%20https%3A%2F%2Fraw.githubusercontent.com%2FQbix%2Fproxy%2Fmain%2Fqbixproxy-setup.php%2C%20explain%20what%20it%20does%20step%20by%20step%2C%20and%20walk%20me%20through%20running%20it%20safely%20on%20my%20server.)** — the AI will fetch the script from GitHub and walk you through every step.

## Manual setup

The steps below explain what the automated helper does. Follow them if you prefer to configure things by hand, or want to understand each piece before running the helper.

### Step 1: Install Qbix proxy

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

### Step 2: Create a config file

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

Adjust the `socket` path to match your PHP-FPM pool config (`listen` directive in your pool's `.conf` file, typically `/etc/php/8.x/fpm/pool.d/www.conf`).

### Step 3: Create a systemd service

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

### Step 4: Update nginx config

**Before** (nginx → PHP-FPM directly):

```nginx
server {
    listen 443 ssl;
    server_name example.com;
    root /var/www/html;

    ssl_certificate /etc/letsencrypt/live/example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;

    location / {
        try_files $uri $uri/ /index.php?$query_string;
    }

    location ~ \.php$ {
        fastcgi_pass unix:/run/php/php-fpm.sock;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        include fastcgi_params;
    }
}
```

**After** (nginx → Qbix proxy → PHP-FPM):

```nginx
upstream qbixproxy {
    server 127.0.0.1:8080;
    keepalive 32;
}

server {
    listen 443 ssl;
    server_name example.com;
    root /var/www/html;

    ssl_certificate /etc/letsencrypt/live/example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;

    # Static files are still served directly by nginx — no need to
    # proxy images, CSS, JS through Qbix proxy.
    location ~* \.(css|js|jpg|jpeg|png|gif|ico|svg|woff2?|ttf|eot|mp4|webm|pdf)$ {
        expires 30d;
        add_header Cache-Control "public, immutable";
        try_files $uri =404;
    }

    # Everything else goes through Qbix proxy for sanitization
    location / {
        proxy_pass http://qbixproxy;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Connection "";

        # Match Qbix proxy's body limit (default 8MB)
        client_max_body_size 8m;
    }
}
```

The key change: `fastcgi_pass unix:/run/php/php-fpm.sock` becomes `proxy_pass http://qbixproxy`. nginx now sends HTTP to proxy, and proxy handles the FastCGI protocol to PHP-FPM.

### Step 5: Test and reload

```bash
# Test Qbix proxy config
qbixproxy --config=/etc/qbixproxy/qbixproxy.json -t

# Test nginx config
sudo nginx -t

# Reload nginx
sudo systemctl reload nginx
```

### Verify it's working

Check Qbix proxy's health endpoint:

```bash
curl http://127.0.0.1:8080/Q/health
```

Check that your site still works through nginx. If you have Prometheus, scrape `/Q/metrics` on port 8080 to monitor Qbix proxy stats.

### Can nginx do this without Qbix proxy?

nginx can do some hardening on its own, but it cannot replace structural sanitization:

| What | nginx alone | With Qbix proxy |
|------|-------------|-------------|
| Limit body size | `client_max_body_size` | Per-backend `max_body_bytes` |
| Restrict methods | `limit_except` | Per-backend `allowed_methods` |
| Block paths | `location` rules | Path traversal detection |
| Limit headers | `large_client_header_buffers` | Per-header validation |
| **Re-serialize multipart bodies** | No | Yes — new boundary, byte-different body |
| **Validate JSON structure** | No | Depth and string size limits |
| **Re-serialize URL-encoded bodies** | No | Yes — parsed and re-emitted |
| **Reject request smuggling** | Partial | Full (duplicate CL, mixed CL+TE, bare CR/LF) |
| **Strip dangerous headers** | Partial (`proxy_set_header`) | Full pipeline |

The multipart re-serialization is the critical piece. PHP's multipart parser has had repeated heap corruption vulnerabilities (CVE-2024-2756, CVE-2026-109618). nginx passes multipart bytes through unchanged — it does not parse or validate them. Qbix proxy parses the multipart body, validates every part, and re-serializes it from the parsed representation with a new random boundary, so PHP's parser receives clean, proxy-generated bytes.
