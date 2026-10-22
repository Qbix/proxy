# Deploying Qbix proxy with Caddy

## Before and after

Most Caddy + PHP deployments use the `php_fastcgi` directive to talk to PHP-FPM:

```
Internet → Caddy :443 (automatic TLS) → php-fpm.sock
```

With Qbix proxy:

```
Internet → Caddy :443 (automatic TLS) → qbixproxy :8080 → php-fpm.sock
```

Caddy still handles TLS (automatic HTTPS), static files, and routing. Qbix proxy handles structural sanitization of every request before it reaches PHP.

## Automated setup (recommended)

The fastest way to configure Caddy is the included PHP helper. It detects your PHP-FPM socket and Caddyfile automatically, shows you a colored preview of every change it will make, then applies everything — binary download, config patches, systemd unit — with a rollback-safe backup:

```bash
# Download the helper
curl -LO https://raw.githubusercontent.com/Qbix/proxy/main/qbixproxy-setup.php

# Step 1: Preview — reads nothing, writes nothing, no root needed
php qbixproxy-setup.php --server=caddy

# Step 2: Apply
sudo php qbixproxy-setup.php --server=caddy
```

If the Caddy config validation (`caddy validate`) fails after patching, the helper restores your original Caddyfile from the `.bak` backup automatically. No reload happens unless validation passes.

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

Adjust the `socket` path to match your PHP-FPM pool config.

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

### Step 4: Update Caddyfile

**Before** (Caddy → PHP-FPM directly):

```caddyfile
example.com {
    root * /var/www/html
    php_fastcgi unix//run/php/php-fpm.sock
    file_server
}
```

**After** (Caddy → Qbix proxy → PHP-FPM):

```caddyfile
example.com {
    root * /var/www/html

    # Static files are still served directly by Caddy
    @static path *.css *.js *.jpg *.jpeg *.png *.gif *.ico *.svg *.woff *.woff2 *.ttf *.eot *.mp4 *.webm *.pdf
    handle @static {
        file_server
    }

    # Everything else goes through Qbix proxy for sanitization
    handle {
        reverse_proxy 127.0.0.1:8080 {
            header_up X-Real-IP {remote_host}
            header_up X-Forwarded-Proto {scheme}
        }
    }
}
```

The key change: `php_fastcgi unix//run/php/php-fpm.sock` becomes `reverse_proxy 127.0.0.1:8080`. Caddy now sends HTTP to Qbix proxy, and Qbix proxy handles the FastCGI protocol to PHP-FPM.

**Minimal change** — if you don't need to optimize static file handling, the smallest possible Caddyfile is:

```caddyfile
example.com {
    reverse_proxy 127.0.0.1:8080 {
        header_up X-Real-IP {remote_host}
        header_up X-Forwarded-Proto {scheme}
    }
}
```

This sends everything through Qbix proxy, including static file requests. Qbix proxy will forward them to PHP-FPM, where PHP can serve them (or return 404). This works but is less efficient than letting Caddy serve static files directly.

### Step 5: Test and reload

```bash
# Test Qbix proxy config
qbixproxy --config=/etc/qbixproxy/qbixproxy.json -t

# Validate Caddyfile
caddy validate --config /etc/caddy/Caddyfile

# Reload Caddy
sudo systemctl reload caddy
```

### Verify it's working

```bash
curl http://127.0.0.1:8080/Q/health
```

Check that your site still works through Caddy. Caddy's automatic HTTPS continues to work — the only change is where PHP requests go after TLS termination.

### Multiple PHP sites

If you run multiple sites on the same server, you can either run one Qbix proxy instance with multiple backends, or one Qbix proxy per site on different ports:

**Option A: One Qbix proxy, multiple backends**

`/etc/qbixproxy/qbixproxy.json`:
```json
{
  "backends": {
    "site1": {
      "socket": "/run/php/site1-fpm.sock",
      "protocol": "fastcgi",
      "document_root": "/var/www/site1",
      "routes": ["/"]
    },
    "site2": {
      "socket": "/run/php/site2-fpm.sock",
      "protocol": "fastcgi",
      "document_root": "/var/www/site2",
      "routes": ["/"]
    }
  }
}
```

Qbix proxy matches backends by the `Host` header and route prefix. Configure each Caddy site to forward to the same Qbix proxy port.

**Option B: Separate Qbix proxy per site**

```caddyfile
site1.example.com {
    reverse_proxy 127.0.0.1:8080
}

site2.example.com {
    reverse_proxy 127.0.0.1:8081
}
```

Each Qbix proxy instance has its own config with site-specific constraints.
