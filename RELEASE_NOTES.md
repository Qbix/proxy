## Qbix proxy v1.0.0

Structural security proxy for PHP. Sits between your web server and PHP-FPM, parsing and re-serializing every HTTP request so PHP's parsers never see attacker-crafted bytes.

### Why this exists

CVE-2026-109618 and CVE-2026-109619 ("php2shell") are critical RCE vulnerabilities in PHP's multipart parser and session.upload_progress handler, affecting every PHP version from 5.4 onward. Only PHP 8.2+ will receive patches. Qbix proxy mitigates these and future parser vulnerabilities by re-serializing request bodies before they reach PHP — no signatures, no rules to update.

### What's in this release

- **6-stage validation pipeline**: Content-Type, method, multipart re-serialization, JSON depth/size, URL-encoded re-serialization, header sanitization
- **Multipart re-serialization**: the core security invariant — multipart bodies are fully parsed, validated, then re-serialized with a new random boundary from `/dev/urandom`
- **Request smuggling prevention**: rejects duplicate Content-Length, mixed CL+TE, bare CR/LF
- **Content-Disposition injection prevention**: rejects `"` and `\` in multipart field names and filenames
- **FastCGI response size cap**: 64 MiB limit prevents backend memory exhaustion
- **Per-backend routing and constraints**: configurable methods, content types, body size, upload limits
- **Prometheus metrics** at `/Q/metrics` and health check at `/Q/health`

### Binaries

| File | Description |
|------|-------------|
| `qbixproxy-linux-x86_64` | Static Linux binary (~160KB), zero dependencies, runs on any Linux system |
| `qbixproxy.com` | [Cosmopolitan](https://github.com/jart/cosmopolitan) APE binary — runs on Linux, macOS, Windows, FreeBSD |
| `SHA256SUMS` | Checksums for both binaries |

### Deployment

See the deployment guides in the repo: [nginx](nginx.md), [Apache](apache.md), [Caddy](caddy.md).

If you use the [Qbix PHP Webserver](https://github.com/Qbix/webserver), Qbix proxy's sanitization is already built in — no separate Qbix proxy needed.

### Build from source

```bash
sudo apt install musl-tools
make static    # produces build/qbixproxy-static (~160KB)
```
