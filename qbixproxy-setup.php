#!/usr/bin/env php
<?php
/**
 * qbixproxy-setup.php  —  Automated setup helper for Qbix proxy
 *
 * ──────────────────────── WHAT THIS SCRIPT DOES ──────────────────────────
 *
 * This script detects your web server configuration (nginx, Apache, or Caddy),
 * then patches the config to route all PHP traffic through Qbix proxy before
 * it reaches PHP-FPM. It also writes the proxy config file and installs a
 * systemd service unit to keep the proxy running.
 *
 * Not sure if this is safe to run? That is exactly what it's designed for.
 * Paste this file into Claude, ChatGPT, or any large language model and ask
 * it to walk you through what the script does step by step. See also:
 * https://github.com/Qbix/proxy#not-sure-if-this-is-safe-to-run
 *
 * ─────────────────────────── WHY THIS HELPS ──────────────────────────────
 *
 * PHP's C-level HTTP parsers (multipart body, session upload progress, SOAP)
 * have a history of critical vulnerabilities. CVE-2026-109618 and
 * CVE-2026-109619 — dubbed "php2shell" — allow unauthenticated remote code
 * execution against any PHP version from 5.4 onward via specially crafted
 * multipart requests.
 *
 * Qbix proxy sits in front of PHP-FPM. For every incoming request, it:
 *   1. Fully parses the request body (multipart, JSON, URL-encoded, etc.)
 *   2. Validates it against configurable size and type limits
 *   3. Re-serializes it from scratch with a new random boundary
 *   4. Forwards only the proxy's clean bytes to PHP-FPM
 *
 * PHP never sees the original attacker-controlled bytes. No signatures, no
 * rules to update, no pattern matching — it's structurally impossible for the
 * attack payload to survive the parse → re-serialize cycle.
 *
 * Architecture after this script runs:
 *
 *   Internet → nginx/Apache/Caddy (TLS, :443)
 *            → Qbix proxy (:8080, localhost only)
 *            → php-fpm.sock
 *
 * ─────────────────────────── TWO-PASS DESIGN ─────────────────────────────
 *
 * Pass 1 — run without sudo (or with --dry-run):
 *   Discovers your PHP-FPM socket and web server configs, then shows
 *   a preview of every change that would be made. Nothing is written.
 *   Nothing is started. Safe to run as many times as you like.
 *
 * Pass 2 — run with sudo:
 *   Writes /etc/qbixproxy/qbixproxy.json and the systemd unit file,
 *   patches each web server config (saving a .bak backup first), tests
 *   the patched config, restores the original if the test fails, then
 *   enables and starts the proxy and reloads the web server.
 *
 *   php qbixproxy-setup.php           # dry run — reads only, shows preview
 *   sudo php qbixproxy-setup.php      # apply — writes, patches, starts service
 *
 * ───────────────────────────────── FLAGS ─────────────────────────────────
 *
 *   --dry-run          Force preview mode even when running as root
 *   --yes              Skip the "Continue?" confirmation prompt
 *   --server=NAME      Patch only one server: nginx | apache | caddy
 *   --help             Show this message and exit
 *
 * ─────────────────────────────── SAFETY ──────────────────────────────────
 *
 * • Every config file is backed up to <file>.bak before any edit.
 * • If the web server's own config test (nginx -t, apachectl -t, etc.)
 *   fails after patching, the original is AUTOMATICALLY restored from
 *   the backup. Your web server is never left in a broken state.
 * • The failed config is saved as <file>.failed for your inspection.
 * • Patching is idempotent: running twice leaves configs unchanged.
 * • Only web server config files are touched — never your PHP source
 *   code, document root, uploaded files, or database.
 *
 * To undo everything manually:
 *   sudo cp /etc/nginx/sites-available/mysite.conf.bak \
 *            /etc/nginx/sites-available/mysite.conf
 *   sudo systemctl stop qbixproxy && sudo systemctl disable qbixproxy
 *   sudo systemctl reload nginx
 */

// ─── parse CLI flags ──────────────────────────────────────────────────────────
// We parse these before any output so --help works cleanly.

$flagDryRun = in_array('--dry-run', $argv ?? []);
$flagYes    = in_array('--yes',     $argv ?? []);
$flagHelp   = in_array('--help',    $argv ?? []) || in_array('-h', $argv ?? []);
$flagServer = null; // --server=nginx | apache | caddy
foreach ($argv ?? [] as $arg) {
    if (preg_match('/^--server=(.+)$/', $arg, $m)) {
        $flagServer = strtolower(trim($m[1]));
    }
}

if ($flagHelp) {
    // Re-print the usage from the docblock above, cleanly
    fwrite(STDOUT, "Qbix proxy setup helper\n\n");
    fwrite(STDOUT, "  php qbixproxy-setup.php           # dry run\n");
    fwrite(STDOUT, "  sudo php qbixproxy-setup.php      # apply\n\n");
    fwrite(STDOUT, "Flags:\n");
    fwrite(STDOUT, "  --dry-run          Preview only — never writes anything\n");
    fwrite(STDOUT, "  --yes              Skip confirmation prompt\n");
    fwrite(STDOUT, "  --server=NAME      nginx | apache | caddy\n");
    fwrite(STDOUT, "  --help             This message\n\n");
    fwrite(STDOUT, "Source: https://github.com/Qbix/proxy\n");
    exit(0);
}

// ─── terminal output helpers ──────────────────────────────────────────────────
// ANSI escape codes for colored terminal output. These are standard and work
// in every modern terminal (macOS Terminal, iTerm2, GNOME Terminal, etc.).
// If you're piping output to a file, colors are invisible — output is clean text.

const RESET = "\033[0m";
const BOLD  = "\033[1m";
const DIM   = "\033[2m";
const GREEN = "\033[32m";
const YELL  = "\033[33m";
const CYAN  = "\033[36m";
const RED   = "\033[31m";

function head(string $t): void { echo "\n" . BOLD . $t . RESET . "\n"; }
function ok  (string $m): void { echo GREEN . "  ✓  " . RESET . $m . "\n"; }
function go  (string $m): void { echo CYAN  . "  →  " . RESET . $m . "\n"; }
function warn(string $m): void { echo YELL  . "  ⚠  " . RESET . $m . "\n"; }
function fail(string $m): void { echo RED   . "  ✗  " . RESET . $m . "\n"; }
function sub (string $m): void { echo DIM   . "       " . $m  . RESET . "\n"; }
function cmd (string $m): void { echo "       " . DIM . "$ " . RESET . $m . "\n"; }
function bar (): void          { echo BOLD . str_repeat("─", 64) . RESET . "\n"; }
function diff_add(string $l): void { echo GREEN . "  +  " . RESET . $l . "\n"; }
function diff_rem(string $l): void { echo RED   . "  -  " . RESET . DIM . $l . RESET . "\n"; }

// ─── filesystem helpers ───────────────────────────────────────────────────────

/**
 * Resolve symlinks to the real underlying file.
 *
 * Why this matters: Debian/Ubuntu use a sites-available / sites-enabled
 * pattern where /etc/nginx/sites-enabled/mysite.conf is a symlink pointing
 * to /etc/nginx/sites-available/mysite.conf. If we patched the symlink entry
 * we'd be writing to a generated path, which might silently fail or create a
 * new regular file next to the symlink, leaving the real config unchanged.
 * By resolving the symlink first, we always patch the canonical source file.
 */
function realFile(string $path): string {
    return is_link($path) ? (string) realpath($path) : $path;
}

function writeFile(string $path, string $content): bool {
    $dir = dirname($path);
    if (!is_dir($dir) && !@mkdir($dir, 0755, true)) {
        fail("Cannot create directory $dir"); return false;
    }
    if (@file_put_contents($path, $content) === false) {
        fail("Cannot write $path"); return false;
    }
    ok("Wrote $path");
    return true;
}

/**
 * Run a shell command with a timeout wrapper.
 *
 * The timeout is important in environments without a running init system
 * (Docker containers, CI, some VPSes). Without it, commands like
 * "systemctl daemon-reload" can hang indefinitely waiting for D-Bus.
 * We default to 30 seconds — more than enough for any config test or
 * service reload, but short enough to fail fast if something is wrong.
 */
function runCmd(string $cmd, string $label, int $timeout = 30): bool {
    $out = []; $rc = 0;
    exec("timeout $timeout sh -c " . escapeshellarg($cmd) . ' 2>&1', $out, $rc);
    if ($rc !== 0) {
        fail($label);
        foreach ($out as $l) if (trim($l) !== '') sub($l);
        return false;
    }
    ok($label);
    return true;
}

/**
 * Try a service reload via systemctl, then fall back to the older 'service'
 * command. This covers systems where systemd is not PID 1 (Docker, WSL 1,
 * some non-systemd distros) as well as older SysV-style setups.
 */
function reloadWebServer(string $name): bool {
    // Map detected server name to its service name
    $svc = match ($name) {
        'nginx'  => 'nginx',
        'apache' => (is_file('/etc/debian_version') ? 'apache2' : 'httpd'),
        'caddy'  => 'caddy',
        default  => $name,
    };

    // systemctl is the modern way on most Linux distros
    if (runCmd("systemctl reload $svc", "$svc reloaded")) return true;

    // Fall back to older SysV 'service' command (still works on most systems
    // even when systemd is present, and is the primary way on some distros)
    return runCmd("service $svc reload", "$svc reloaded (via service)");
}

// ─── discovery: qbixproxy binary ─────────────────────────────────────────────

/**
 * Find the qbixproxy binary.
 *
 * We check common install locations first, then fall back to PATH lookup.
 * The binary must be executable — a zero-byte file or wrong permissions
 * would fail the is_executable check.
 */
function findBinary(): ?string {
    foreach (['/usr/local/bin/qbixproxy', '/usr/bin/qbixproxy'] as $p) {
        if (@is_executable($p)) return $p;
    }
    $r = trim((string) shell_exec('which qbixproxy 2>/dev/null'));
    return $r ?: null;
}

// ─── discovery: PHP-FPM socket ───────────────────────────────────────────────

/**
 * Find the PHP-FPM Unix socket that Qbix proxy will forward requests to.
 *
 * PHP-FPM listens on a Unix socket (a special file in /run/php/ or similar).
 * We need this path for two things:
 *   1. The qbixproxy.json config file, so the proxy knows where to send requests
 *   2. Sanity-checking that PHP-FPM is actually running
 *
 * We try two methods:
 *   a) Look for existing socket files (they only exist while php-fpm is running)
 *   b) Parse PHP-FPM pool config files for "listen = /path/to.sock" directives
 *      (catches sockets that exist but aren't active yet)
 *
 * When multiple PHP versions are installed, we prefer the highest version
 * (e.g. php8.3-fpm over php7.4-fpm) since that's almost always what you want.
 */
function findFpmSocket(): ?string {
    $candidates = [];

    // Method a: look for existing socket files
    // These glob patterns cover Debian (/run/php/), RHEL (/run/php-fpm/),
    // and distros that still use /var/run/ instead of /run/
    foreach ([
        '/run/php/php*.sock',
        '/var/run/php/php*.sock',
        '/run/php-fpm/*.sock',
        '/var/run/php-fpm/*.sock',
    ] as $g) {
        foreach (glob($g) ?: [] as $s) {
            // filetype() distinguishes socket files from regular files
            if (@filetype($s) === 'socket') $candidates[$s] = $s;
        }
    }

    // Method b: parse pool config "listen" directives
    // Pool .conf files specify where FPM listens even when FPM isn't running yet
    foreach (['/etc/php/*/fpm/pool.d/*.conf', '/etc/php-fpm.d/*.conf'] as $g) {
        foreach (glob($g) ?: [] as $f) {
            $c = (string) @file_get_contents($f);
            if (preg_match('/^listen\s*=\s*(\/[^\s\r\n]+\.sock)/m', $c, $m)) {
                if (@file_exists($m[1])) $candidates[$m[1]] = $m[1];
            }
        }
    }

    if (empty($candidates)) return null;

    // Sort by PHP version number descending (e.g. php8.3 before php7.4)
    uksort($candidates, function ($a, $b) {
        preg_match('/(\d+\.\d+)/', $a, $ma);
        preg_match('/(\d+\.\d+)/', $b, $mb);
        return version_compare($mb[1] ?? '0', $ma[1] ?? '0');
    });

    return array_key_first($candidates);
}

// ─── discovery: service user ──────────────────────────────────────────────────

/**
 * Detect what OS user the PHP-FPM pool runs as.
 *
 * Qbix proxy must connect to the PHP-FPM socket, so it needs to run as a
 * user that has permission to read/write that socket. The safest choice is
 * to run as the same user PHP-FPM's pool is configured for.
 *
 * We check:
 *   1. The pool config "user =" line (most reliable)
 *   2. Known defaults for common distros (www-data on Debian, apache on RHEL)
 *   3. Fall back to www-data if nothing is found
 */
function detectServiceUser(): string {
    // Read from PHP-FPM pool configs — look for "user = www-data" style lines
    foreach (glob('/etc/php/*/fpm/pool.d/*.conf') ?: [] as $f) {
        $c = (string) @file_get_contents($f);
        if (preg_match('/^\s*user\s*=\s*(\w[\w-]*)/m', $c, $m)) {
            // Verify this user actually exists on the system
            if (function_exists('posix_getpwnam') && posix_getpwnam($m[1]) !== false) {
                return $m[1];
            }
        }
    }

    // Common defaults: www-data (Debian/Ubuntu), apache (RHEL/CentOS/Fedora),
    // nginx (Alpine/Arch), nobody (FreeBSD-style setups)
    foreach (['www-data', 'apache', 'nginx', 'http', 'nobody'] as $u) {
        if (function_exists('posix_getpwnam') && posix_getpwnam($u) !== false) return $u;
        if (trim((string) shell_exec("id -u $u 2>/dev/null")) !== '') return $u;
    }

    return 'www-data'; // last resort default
}

// ─── web server detection ─────────────────────────────────────────────────────

/**
 * Strip # comment lines from a config before scanning for PHP directives.
 *
 * Why: nginx, Apache, and Caddy all use # for comments. The Debian-packaged
 * default nginx config has commented-out fastcgi_pass examples:
 *   # fastcgi_pass unix:/run/php/php7.4-fpm.sock;
 * Without comment stripping, we'd incorrectly flag that file as a PHP config
 * that needs patching, when it's actually just the commented example.
 */
function stripComments(string $txt): string {
    return (string) preg_replace('/^\s*#[^\n]*/m', '', $txt);
}

/**
 * Find nginx virtual host config files that handle PHP via FastCGI.
 *
 * We search both sites-enabled/ (active symlinks) and conf.d/ (drop-in configs).
 * For each file, we strip comments then look for "fastcgi_pass" — that's the
 * nginx directive that means "send this request directly to PHP-FPM". That's
 * the directive we're replacing with "proxy_pass http://qbixproxy".
 *
 * We store both the symlink path (for display) and the real file path
 * (for patching), so we always edit the canonical source in sites-available/.
 */
function findNginxPhpFiles(): array {
    $found = [];
    // sites-enabled/ contains symlinks; conf.d/ contains real files
    // RedHat-family distros only use conf.d/ (no sites-enabled pattern)
    $dirs = ['/etc/nginx/sites-enabled', '/etc/nginx/conf.d'];
    foreach ($dirs as $dir) {
        if (!is_dir($dir)) continue;
        foreach (array_merge(glob("$dir/*.conf") ?: [], glob("$dir/*") ?: []) as $f) {
            if (!is_file($f) && !is_link($f)) continue;
            $real = realFile($f);
            // Strip comments before checking — avoids false positives from examples
            $c = stripComments((string) @file_get_contents($real));
            if (stripos($c, 'fastcgi_pass') !== false && !isset($found[$real])) {
                $found[$real] = ['link' => $f, 'real' => $real, 'source' => $dir];
            }
        }
    }
    // Fallback: some setups define PHP handling directly in nginx.conf
    if (empty($found)) {
        $f = '/etc/nginx/nginx.conf';
        $c = stripComments((string) @file_get_contents($f));
        if (is_file($f) && stripos($c, 'fastcgi_pass') !== false) {
            $found[$f] = ['link' => $f, 'real' => $f, 'source' => 'nginx.conf'];
        }
    }
    return array_values($found);
}

/**
 * Find Apache virtual host configs that handle PHP via mod_proxy_fcgi.
 *
 * Apache connects to PHP-FPM using mod_proxy_fcgi, which appears in configs as:
 *   <FilesMatch \.php$>
 *       SetHandler "proxy:unix:/run/php/php8.3-fpm.sock|fcgi://localhost"
 *   </FilesMatch>
 * or as:
 *   ProxyPassMatch ^/(.*\.php(/.*)?)$ unix:/run/php/php8.3-fpm.sock|fcgi://...
 *
 * We look for any of these patterns (case-insensitive, comments stripped)
 * to identify configs that need patching.
 */
function findApachePhpFiles(): array {
    $found = [];
    // Debian uses sites-enabled/, RedHat uses conf.d/ under /etc/httpd/
    $dirs = ['/etc/apache2/sites-enabled', '/etc/apache2/conf.d', '/etc/httpd/conf.d'];
    foreach ($dirs as $dir) {
        if (!is_dir($dir)) continue;
        foreach (array_merge(glob("$dir/*.conf") ?: [], glob("$dir/*") ?: []) as $f) {
            if (!is_file($f) && !is_link($f)) continue;
            $real = realFile($f);
            $c = stripComments((string) @file_get_contents($real));
            // Match FilesMatch PHP handler, mod_proxy_fcgi SetHandler, or ProxyPassMatch
            if (preg_match('/FilesMatch.*php|SetHandler.*fcgi|proxy:unix|ProxyPassMatch.*php/i', $c)
                && !isset($found[$real])
            ) {
                $found[$real] = ['link' => $f, 'real' => $real, 'source' => $dir];
            }
        }
    }
    return array_values($found);
}

/**
 * Find Caddy configs that handle PHP via php_fastcgi.
 *
 * Caddy makes PHP setup very simple with a single "php_fastcgi" directive:
 *   php_fastcgi unix//run/php/php8.3-fpm.sock
 *
 * This is Caddy's built-in shorthand that internally uses FastCGI. We replace
 * it with a reverse_proxy block that uses HTTP to talk to Qbix proxy instead.
 */
function findCaddyPhpFiles(): array {
    $found = [];
    $candidates = [
        '/etc/caddy/Caddyfile',           // Debian/Ubuntu package
        '/usr/local/etc/caddy/Caddyfile', // Homebrew/manual install
    ];
    // Some setups split Caddyfile into per-site files in conf.d/
    foreach (glob('/etc/caddy/conf.d/*.caddy') ?: [] as $f) $candidates[] = $f;
    foreach (glob('/etc/caddy/conf.d/*.conf')  ?: [] as $f) $candidates[] = $f;

    foreach ($candidates as $f) {
        if (!is_file($f)) continue;
        $real = realFile($f);
        $c = (string) @file_get_contents($real);
        if (stripos($c, 'php_fastcgi') !== false && !isset($found[$real])) {
            $found[$real] = ['link' => $f, 'real' => $real, 'source' => dirname($f)];
        }
    }
    return array_values($found);
}

/**
 * Detect which web servers are installed and have PHP configs to patch.
 *
 * Returns an array of ['server_name' => [array of file entries]].
 * Each file entry has 'link' (displayed path), 'real' (file to patch),
 * and 'source' (directory it came from).
 */
function detectWebServers(): array {
    $detected = [];

    // nginx — check common binary locations, then PATH
    if (is_executable('/usr/sbin/nginx') || is_executable('/usr/bin/nginx')
        || trim((string) shell_exec('which nginx 2>/dev/null')) !== '')
    {
        $files = findNginxPhpFiles();
        if ($files) $detected['nginx'] = $files;
    }

    // apache2 / httpd — Debian calls it apache2, RHEL calls it httpd
    $apacheBin = null;
    foreach (['/usr/sbin/apache2', '/usr/sbin/httpd', '/usr/bin/apache2'] as $b) {
        if (is_executable($b)) { $apacheBin = $b; break; }
    }
    if (!$apacheBin) {
        $r = trim((string) shell_exec('which apache2 2>/dev/null || which httpd 2>/dev/null'));
        if ($r) $apacheBin = $r;
    }
    if ($apacheBin) {
        $files = findApachePhpFiles();
        if ($files) $detected['apache'] = $files;
    }

    // caddy
    if (is_executable('/usr/bin/caddy') || is_executable('/usr/local/bin/caddy')
        || trim((string) shell_exec('which caddy 2>/dev/null')) !== '')
    {
        $files = findCaddyPhpFiles();
        if ($files) $detected['caddy'] = $files;
    }

    return $detected;
}

// ─── nginx config patching ────────────────────────────────────────────────────

/**
 * Walk forward from an opening brace, return the position of its matching
 * closing brace.
 *
 * nginx/Caddy configs use nested braces for blocks. We need to find the
 * end of location { } and server { } blocks without a full parser. This
 * simple depth counter handles arbitrary nesting correctly as long as
 * braces inside strings are rare (they are, in these config formats).
 */
function matchBrace(string $txt, int $pos): int {
    $depth = 0;
    for ($i = $pos, $n = strlen($txt); $i < $n; $i++) {
        if ($txt[$i] === '{') $depth++;
        elseif ($txt[$i] === '}' && --$depth === 0) return $i;
    }
    return -1; // unmatched brace (malformed config)
}

/**
 * Remove all nginx location blocks that contain a fastcgi_pass directive.
 *
 * These blocks are the ones that currently send PHP requests directly to
 * PHP-FPM. They look like:
 *
 *   location ~ \.php$ {
 *       include snippets/fastcgi-php.conf;
 *       fastcgi_pass unix:/run/php/php8.3-fpm.sock;
 *       ...
 *   }
 *
 * We remove them entirely so we can replace them with a single
 * "location / { proxy_pass http://qbixproxy; }" block.
 */
function removeNginxPhpLocations(string $txt): string {
    $offset = 0;
    // Match any "location <pattern> {" line (the \n prefix anchors to a new line)
    while (preg_match('/\n[ \t]*location\s+[^\n{]+\{/s', $txt, $m, PREG_OFFSET_CAPTURE, $offset)) {
        $lineStart  = $m[0][1];
        $braceOpen  = $lineStart + strlen($m[0][0]) - 1;
        $braceClose = matchBrace($txt, $braceOpen);
        if ($braceClose === -1) { $offset = $lineStart + 1; continue; }
        $block = substr($txt, $braceOpen, $braceClose - $braceOpen + 1);
        if (stripos($block, 'fastcgi_pass') !== false) {
            // Remove this block (from the newline before "location" to the closing })
            $txt = substr($txt, 0, $lineStart) . substr($txt, $braceClose + 1);
            // Don't advance offset — the text shifted left, retry at same position
        } else {
            $offset = $braceClose + 1;
        }
    }
    return $txt;
}

/**
 * Remove the generic "location / { ... }" block if it doesn't contain
 * proxy_pass or fastcgi_pass.
 *
 * Why: many nginx PHP configs include a bare "location / { try_files ... }"
 * block for handling requests before the PHP location. Once we add our own
 * "location / { proxy_pass http://qbixproxy; }" there can only be one
 * catch-all location / block, so we remove the old one.
 *
 * We keep it if it already has proxy_pass (already patched) or fastcgi_pass
 * (will be removed by removeNginxPhpLocations instead).
 */
function removeNginxSlashLocation(string $txt): string {
    $offset = 0;
    while (preg_match('/\n[ \t]*location\s+\/\s*\{/', $txt, $m, PREG_OFFSET_CAPTURE, $offset)) {
        $lineStart  = $m[0][1];
        $braceOpen  = $lineStart + strlen($m[0][0]) - 1;
        $braceClose = matchBrace($txt, $braceOpen);
        if ($braceClose === -1) { $offset = $lineStart + 1; continue; }
        $block = substr($txt, $braceOpen, $braceClose - $braceOpen + 1);
        if (stripos($block, 'proxy_pass') === false && stripos($block, 'fastcgi_pass') === false) {
            $txt = substr($txt, 0, $lineStart) . substr($txt, $braceClose + 1);
        } else {
            $offset = $braceClose + 1;
        }
    }
    return $txt;
}

/**
 * Patch an nginx virtual host config to route PHP through Qbix proxy.
 *
 * Before:
 *   server {
 *       location ~ \.php$ { fastcgi_pass unix:/run/php/...; }
 *       location / { try_files ...; }
 *   }
 *
 * After:
 *   upstream qbixproxy { server 127.0.0.1:8080; keepalive 32; }
 *   server {
 *       location ~* \.(css|js|jpg|...)$ { expires 30d; try_files ...; }
 *       location / { proxy_pass http://qbixproxy; ... }
 *   }
 *
 * The upstream block with keepalive 32 lets nginx reuse connections to
 * Qbix proxy rather than opening a new TCP connection per request — an
 * important performance optimization, since both processes are on the
 * same machine (127.0.0.1:8080).
 *
 * Static files (CSS, JS, images) are still served by nginx directly.
 * There's no reason to run them through the proxy — only PHP requests
 * need the sanitization that Qbix proxy provides.
 */
function patchNginx(string $txt): string {
    // Idempotency guard: if this config already has our upstream block,
    // it's already patched — return unchanged
    if (strpos($txt, 'upstream qbixproxy') !== false) return $txt;

    // Step 1: Remove existing PHP FastCGI location blocks
    $txt = removeNginxPhpLocations($txt);

    // Step 2: Remove the generic location / {} block (we'll add our own)
    $txt = removeNginxSlashLocation($txt);

    // Step 3: Add the upstream block just before the first server { }
    // nginx's upstream directive must appear at the http { } level, before server { }
    $upstream = "upstream qbixproxy {\n    server 127.0.0.1:8080;\n    keepalive 32;\n}\n\n";
    $txt = preg_replace('/(\bserver\s*\{)/', $upstream . '$1', $txt, 1) ?? $txt;

    // Step 4: Define the replacement location blocks
    // We use a heredoc for readability — the indentation matches typical nginx style
    $locations = <<<'NGINX'

    # Static files — served directly by nginx for performance.
    # Images, CSS, JS etc. don't need the Qbix proxy sanitation pipeline.
    location ~* \.(css|js|jpg|jpeg|png|gif|ico|svg|woff2?|ttf|eot|mp4|webm|pdf)$ {
        expires 30d;
        add_header Cache-Control "public, immutable";
        try_files $uri =404;
    }

    # Everything else (including all PHP requests) → Qbix proxy → PHP-FPM.
    # proxy_http_version 1.1 + Connection "" enables HTTP keepalive to the proxy.
    location / {
        proxy_pass http://qbixproxy;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Connection "";
        client_max_body_size 8m;
    }
NGINX;

    // Step 5: Insert the new location blocks before the closing } of the
    // last server { } block. We scan for all server blocks to find the last one.
    $lastClose = -1;
    $offset = 0;
    while (preg_match('/\bserver\s*\{/', $txt, $m, PREG_OFFSET_CAPTURE, $offset)) {
        $bo = $m[0][1] + strlen($m[0][0]) - 1;
        $bc = matchBrace($txt, $bo);
        if ($bc === -1) break;
        $lastClose = $bc;
        $offset    = $bc + 1;
    }
    if ($lastClose !== -1) {
        $txt = substr($txt, 0, $lastClose) . $locations . "\n" . substr($txt, $lastClose);
    }

    // Clean up: collapse runs of 3+ blank lines to 2
    return (string) preg_replace('/\n{3,}/', "\n\n", $txt);
}

// ─── apache config patching ───────────────────────────────────────────────────

/**
 * Patch an Apache virtual host config to route PHP through Qbix proxy.
 *
 * Before (using mod_proxy_fcgi):
 *   <VirtualHost *:443>
 *       <FilesMatch \.php$>
 *           SetHandler "proxy:unix:/run/php/php8.3-fpm.sock|fcgi://localhost"
 *       </FilesMatch>
 *   </VirtualHost>
 *
 * After (using mod_proxy_http → Qbix proxy):
 *   <VirtualHost *:443>
 *       ProxyPreserveHost On
 *       ProxyPass / http://127.0.0.1:8080/
 *       ProxyPassReverse / http://127.0.0.1:8080/
 *       RequestHeader set X-Real-IP "%{REMOTE_ADDR}s"
 *       RequestHeader set X-Forwarded-Proto "%{REQUEST_SCHEME}s"
 *   </VirtualHost>
 *
 * ProxyPreserveHost On: tells Apache to forward the original Host: header
 * to Qbix proxy, which in turn forwards it to PHP-FPM. Without this,
 * $_SERVER['HTTP_HOST'] in PHP would show "127.0.0.1:8080" instead of
 * the real domain name.
 *
 * The RequestHeader lines inject real client IP and protocol into headers
 * that PHP can read as $_SERVER['HTTP_X_REAL_IP'] and
 * $_SERVER['HTTP_X_FORWARDED_PROTO']. Your PHP code can use these to
 * know the original client's IP even though the immediate connection
 * comes from the local proxy.
 *
 * Note: Apache also needs mod_proxy, mod_proxy_http, and mod_headers enabled.
 * This script runs a2enmod for those automatically on Debian/Ubuntu.
 */
function patchApache(string $txt): string {
    // Idempotency guard
    if (stripos($txt, 'ProxyPass / http://127.0.0.1:8080') !== false) return $txt;

    // Step 1: Remove <FilesMatch \.php$> ... </FilesMatch> blocks entirely.
    // The regex uses 'is' flags: i=case-insensitive, s=dot matches newlines
    // (so .*? spans the multiple lines inside the FilesMatch block).
    $txt = preg_replace(
        '/<FilesMatch\s+["\']?\\\\?\.php["\']?[^>]*>.*?<\/FilesMatch>/is',
        '',
        $txt
    ) ?? $txt;

    // Step 2: Remove standalone SetHandler "proxy:..." lines
    // (some configs use this outside a FilesMatch block)
    $txt = preg_replace('/[ \t]*SetHandler\s+"proxy:[^"\n]+"[ \t]*\n/i', '', $txt) ?? $txt;

    // Step 3: Remove ProxyPassMatch ^/.*\.php$ lines
    // (another common pattern for PHP-FPM proxying in Apache)
    $txt = preg_replace('/[ \t]*ProxyPassMatch\s+[^\n]*\.php[^\n]*\n/i', '', $txt) ?? $txt;

    // Step 4: Insert our ProxyPass directives before </VirtualHost>
    $proxy = <<<'APACHE'

    # All requests → Qbix proxy → PHP-FPM.
    # Qbix proxy listens on localhost:8080 and sanitizes every request
    # before forwarding to PHP-FPM via FastCGI on its Unix socket.
    ProxyPreserveHost On
    ProxyPass / http://127.0.0.1:8080/
    ProxyPassReverse / http://127.0.0.1:8080/
    RequestHeader set X-Real-IP "%{REMOTE_ADDR}s"
    RequestHeader set X-Forwarded-Proto "%{REQUEST_SCHEME}s"

APACHE;
    $txt = preg_replace('/<\/VirtualHost>/i', $proxy . '</VirtualHost>', $txt, 1) ?? $txt;

    // Clean up: collapse blank lines
    return (string) preg_replace('/\n{3,}/', "\n\n", $txt);
}

// ─── caddy config patching ────────────────────────────────────────────────────

/**
 * Patch a Caddyfile to route PHP through Qbix proxy.
 *
 * Before:
 *   example.com {
 *       root * /var/www/html
 *       php_fastcgi unix//run/php/php8.3-fpm.sock
 *       file_server
 *       encode gzip
 *   }
 *
 * After:
 *   example.com {
 *       root * /var/www/html
 *       encode gzip
 *       @static path *.css *.js *.jpg ...
 *       handle @static { file_server }
 *       handle { reverse_proxy 127.0.0.1:8080 { ... } }
 *   }
 *
 * Why we replace both php_fastcgi AND file_server:
 * Caddy's php_fastcgi is a shorthand that expands to FastCGI + file_server
 * internally. Once we replace php_fastcgi, the remaining standalone
 * file_server directive would serve ALL requests as static files, which
 * would break PHP. We replace both with two explicit handle blocks:
 *   - @static handle: Caddy serves matching file extensions directly (fast)
 *   - default handle: everything else goes through Qbix proxy
 *
 * The header_up directives pass the real client IP and protocol to the
 * proxy (and onward to PHP) so $_SERVER['HTTP_X_REAL_IP'] works correctly.
 */
function patchCaddy(string $txt): string {
    // Idempotency guard — MUST be checked BEFORE any removals below.
    // If we're already patched, the file contains "reverse_proxy 127.0.0.1:8080"
    // inside our handle @static block's sibling, which also contains "file_server".
    // If we ran the removals first, we'd strip our own file_server on re-run.
    if (strpos($txt, 'reverse_proxy 127.0.0.1:8080') !== false) return $txt;

    // Step 1: Remove the php_fastcgi directive
    // "php_fastcgi" can be followed by a Unix socket path or TCP address
    $txt = preg_replace('/[ \t]*php_fastcgi[^\n]*\n/i', '', $txt) ?? $txt;

    // Step 2: Remove the standalone "file_server" line.
    // We use ^...$ anchoring (via /m flag) to match only a line that is
    // JUST "file_server" (possibly with leading whitespace), not "file_server"
    // inside a block with other directives. This avoids removing "file_server"
    // from inside our replacement "handle @static { file_server }" block.
    $txt = preg_replace('/^[ \t]*file_server[ \t]*\n/m', '', $txt) ?? $txt;

    // Step 3: Define the replacement blocks
    $replacement = <<<'CADDY'
    @static path *.css *.js *.jpg *.jpeg *.png *.gif *.ico *.svg *.woff *.woff2 *.ttf *.eot *.mp4 *.webm *.pdf

    # Static files — served directly by Caddy (fast, no proxy overhead)
    handle @static {
        file_server
    }

    # Everything else → Qbix proxy → PHP-FPM
    handle {
        reverse_proxy 127.0.0.1:8080 {
            header_up X-Real-IP {remote_host}
            header_up X-Forwarded-Proto {scheme}
        }
    }
CADDY;

    // Step 4: Insert before the closing } of the first site block
    // Caddy site blocks look like: example.com { ... }
    if (preg_match('/\{/', $txt, $m, PREG_OFFSET_CAPTURE)) {
        $bo = $m[0][1];
        $bc = matchBrace($txt, $bo);
        if ($bc !== -1) {
            $txt = substr($txt, 0, $bc) . "\n" . $replacement . "\n" . substr($txt, $bc);
        }
    }
    return $txt;
}

// ─── dry-run diff preview ─────────────────────────────────────────────────────

/**
 * Show the key lines that will change in a config file.
 *
 * Rather than dumping the full diff, we highlight only the lines that matter
 * for security: the PHP directives being removed (-) and the proxy directives
 * being added (+). This gives a clear, scannable answer to "what exactly
 * will this script change in my config?"
 */
function showKeyChanges(string $server, string $orig, string $patched): void {
    $origLines    = array_map('rtrim', explode("\n", $orig));
    $patchedLines = array_map('rtrim', explode("\n", $patched));

    // Build lookup sets for fast comparison
    $origSet    = array_flip($origLines);
    $patchedSet = array_flip($patchedLines);

    // Patterns for lines we're removing (PHP-to-FPM directives)
    $removePattern = '/fastcgi_pass|php_fastcgi|FilesMatch.*php|SetHandler.*fcgi|proxy:unix|ProxyPassMatch/i';

    // Patterns for key lines we're adding (proxy directives)
    $addPattern = '/proxy_pass\s+http:\/\/qbixproxy|ProxyPass\s+\/\s+http:\/\/127|'
                . 'reverse_proxy\s+127\.0\.0\.1:8080|upstream\s+qbixproxy|'
                . 'ProxyPreserveHost|handle_up\s+X-Real|header_up\s+X-Real/i';

    $shown = 0;
    foreach ($origLines as $line) {
        $t = rtrim($line);
        if ($t !== '' && preg_match($removePattern, $t) && !isset($patchedSet[$t])) {
            diff_rem(trim($line));
            $shown++;
        }
    }
    foreach ($patchedLines as $line) {
        $t = rtrim($line);
        if ($t !== '' && preg_match($addPattern, $t) && !isset($origSet[$t])) {
            diff_add(trim($line));
            $shown++;
        }
    }
    if ($shown === 0) {
        sub("(no key PHP directives changed — already patched or nothing to change)");
    }
}

// ─── config file generators ───────────────────────────────────────────────────

/**
 * Generate the qbixproxy.json config file.
 *
 * This tells Qbix proxy:
 *   - Where PHP-FPM's Unix socket is (so it can forward validated requests)
 *   - What document root to use (passed as DOCUMENT_ROOT in FastCGI variables)
 *   - What constraints to enforce (max body size, allowed methods, upload limits)
 *
 * The constraints are reasonable defaults. Edit /etc/qbixproxy/qbixproxy.json
 * after setup if your application needs different limits (e.g. larger uploads).
 */
function makeQbixproxyJson(string $socket, string $docRoot): string {
    return json_encode([
        'backends' => [
            'php' => [
                'socket'        => $socket,
                'protocol'      => 'fastcgi',      // talk FastCGI to PHP-FPM
                'document_root' => $docRoot,        // sets DOCUMENT_ROOT in FastCGI env
                'routes'        => ['/'],           // handle all paths
                'constraints'   => [
                    // Maximum total request body size (8 MB default)
                    'max_body_bytes'  => 8388608,
                    'allowed_methods' => ['GET','POST','PUT','PATCH','DELETE','HEAD','OPTIONS'],
                    // Only accept these Content-Type values; others get 415 Unsupported
                    'allowed_content_types' => [
                        'application/x-www-form-urlencoded',
                        'multipart/form-data',
                        'application/json',
                        'text/plain',
                    ],
                    'upload' => [
                        'max_files'          => 20,        // max files per multipart request
                        'max_file_bytes'     => 10485760,  // 10 MB per file
                        // Whitelist of allowed file upload extensions
                        'allowed_extensions' => [
                            '.jpg','.jpeg','.png','.gif','.webp',
                            '.pdf','.zip','.doc','.docx','.xls','.xlsx',
                        ],
                    ],
                ],
            ],
        ],
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n";
}

/**
 * Generate the systemd service unit file for qbixproxy.
 *
 * Key security settings in the [Service] section:
 *   User/Group: Run as the web server's user (same as PHP-FPM's pool user),
 *     not root. This ensures the process can access the FPM socket.
 *   NoNewPrivileges: The process can never gain elevated privileges via
 *     setuid/setgid or Linux capabilities — even if the binary is exploited.
 *   ProtectSystem=strict: The entire filesystem is read-only except for
 *     /run, /tmp, and paths explicitly opened for writing.
 *   ProtectHome: Blocks access to /home, /root, /run/user.
 *   PrivateTmp: The process gets its own private /tmp that no other process
 *     can see or write to.
 *   ReadOnlyPaths=/etc/qbixproxy: The config directory is readable but the
 *     process cannot modify it even if compromised.
 *
 * If the proxy process were ever exploited, these limits ensure the attacker
 * has a process that can open network sockets and read its own config, and
 * nothing else — it cannot read your PHP source code, your database config,
 * your user's home directories, or write anywhere on disk.
 */
function makeSystemdUnit(string $serviceUser = 'www-data'): string {
    return <<<UNIT
[Unit]
Description=Qbix proxy — structural security proxy for PHP
Documentation=https://github.com/Qbix/proxy
After=network.target php-fpm.service
Wants=php-fpm.service

[Service]
Type=simple
ExecStart=/usr/local/bin/qbixproxy --config=/etc/qbixproxy/qbixproxy.json --port=8080 --host=127.0.0.1
Restart=always
RestartSec=2

# Security hardening — if the proxy process is ever compromised, the attacker
# gets a process that can open sockets and nothing else.
User=$serviceUser
Group=$serviceUser
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadOnlyPaths=/etc/qbixproxy

[Install]
WantedBy=multi-user.target
UNIT;
}

// ─── per-server patch + validate + rollback ───────────────────────────────────

/**
 * Patch one web server config file, validate it, and roll back on failure.
 *
 * Flow:
 *   1. Check if already patched (idempotent)
 *   2. Generate the patched text and show a key-changes diff
 *   3. In apply mode: back up the original, write the patch, run config test
 *   4. If the config test fails: restore from backup, save failed attempt
 *
 * @param array{link:string,real:string,source:string} $entry
 */
function patchAndApplyServer(
    string $server,
    array  $entry,
    bool   $dryRun
): bool {
    $real     = $entry['real'];
    $link     = $entry['link'];
    $linkNote = ($link !== $real) ? DIM . "  (symlink → $real)" . RESET : '';

    sub("$link$linkNote");

    $orig = (string) @file_get_contents($real);
    if ($orig === '') {
        warn("Could not read $real — skipping");
        return false;
    }

    // Check if this config was already patched by a previous run
    $alreadyPatched = match ($server) {
        'nginx'  => strpos($orig, 'upstream qbixproxy') !== false,
        'apache' => stripos($orig, 'ProxyPass / http://127.0.0.1:8080') !== false,
        'caddy'  => strpos($orig, 'reverse_proxy 127.0.0.1:8080') !== false,
        default  => false,
    };
    if ($alreadyPatched) {
        ok("Already patched — no changes needed");
        return true;
    }

    // Generate the patched version
    $patched = match ($server) {
        'nginx'  => patchNginx($orig),
        'apache' => patchApache($orig),
        'caddy'  => patchCaddy($orig),
        default  => $orig,
    };

    // Show what's changing (key lines removed/added)
    showKeyChanges($server, $orig, $patched);

    $origLines    = substr_count($orig,    "\n");
    $patchedLines = substr_count($patched, "\n");
    $delta = $patchedLines - $origLines;
    sub("$origLines lines → $patchedLines lines  (" . ($delta >= 0 ? "+$delta" : "$delta") . ")");

    // In dry-run mode we stop here — nothing is written
    if ($dryRun) return true;

    // Back up the original before touching anything
    $backup = $real . '.bak';
    if (!@copy($real, $backup)) {
        fail("Cannot create backup $backup");
        sub("Check permissions on " . dirname($real));
        return false;
    }
    ok("Backed up → $backup");

    // Write the patched config
    if (@file_put_contents($real, $patched) === false) {
        fail("Cannot write $real");
        @copy($backup, $real); // try to restore if write partially failed
        return false;
    }
    ok("Patched $real");

    // Run the web server's own config validator.
    // We use 'timeout' to prevent hanging in environments without init systems.
    [$testCmd, $testLabel] = match ($server) {
        'nginx'  => ['nginx -t', 'nginx config test'],
        'apache' => ['apachectl -t 2>&1 || apache2ctl -t 2>&1', 'apache config test'],
        'caddy'  => [
            'caddy validate --config ' . escapeshellarg(
                is_file('/etc/caddy/Caddyfile') ? '/etc/caddy/Caddyfile' : $real
            ),
            'caddy validate',
        ],
        default  => ['true', 'config test (skipped)'],
    };

    $out = []; $rc = 0;
    exec("timeout 30 sh -c " . escapeshellarg($testCmd) . ' 2>&1', $out, $rc);

    if ($rc !== 0) {
        fail("$testLabel failed — restoring original from backup");
        foreach ($out as $l) if (trim($l) !== '') sub($l);

        // Restore backup
        if (@copy($backup, $real)) {
            ok("Original restored from $backup");
        } else {
            fail("COULD NOT RESTORE BACKUP — manual intervention required");
            sub("Run: sudo cp $backup $real");
        }

        // Save the failed patch for inspection
        @file_put_contents($real . '.failed', $patched);
        sub("Failed attempt saved to $real.failed for inspection");
        return false;
    }

    ok("$testLabel passed");
    return true;
}

// ─── main ─────────────────────────────────────────────────────────────────────

// Determine effective mode: dry run if not root, or if --dry-run was passed
$isRoot = (trim((string) shell_exec('id -u 2>/dev/null')) === '0');
$dryRun = !$isRoot || $flagDryRun;

// ─── header ───────────────────────────────────────────────────────────────────
bar();
echo BOLD . "  Qbix proxy setup" . DIM
   . "  (" . ($dryRun ? "preview only — nothing will be written" : "applying changes") . ")"
   . RESET . "\n";
bar();

if ($dryRun && $isRoot && $flagDryRun) {
    // Running as root with explicit --dry-run
    warn("--dry-run passed: running in preview mode even though you are root");
}

// ── Step 1: Locate the qbixproxy binary ──────────────────────────────────────
head("1. Binary");

$binary = findBinary();
if (!$binary) {
    fail("qbixproxy not found in /usr/local/bin, /usr/bin, or PATH");
    echo "\n";
    sub("Download the binary for your platform:");
    cmd("# Linux x86_64:");
    cmd("curl -LO https://github.com/Qbix/proxy/releases/latest/download/qbixproxy-linux-x86_64");
    cmd("chmod +x qbixproxy-linux-x86_64 && sudo mv qbixproxy-linux-x86_64 /usr/local/bin/qbixproxy");
    echo "\n";
    cmd("# Linux ARM64 (AWS Graviton, Ampere, Raspberry Pi):");
    cmd("curl -LO https://github.com/Qbix/proxy/releases/latest/download/qbixproxy-linux-aarch64");
    cmd("chmod +x qbixproxy-linux-aarch64 && sudo mv qbixproxy-linux-aarch64 /usr/local/bin/qbixproxy");
    echo "\n";
    sub("Then run this script again.");
    exit(1);
}

ok("Found at $binary");
$sz = @filesize($binary);
if ($sz) sub(number_format($sz / 1024, 0) . " KB");

// ── Step 2: Find the PHP-FPM socket ──────────────────────────────────────────
head("2. PHP-FPM socket");

$socket = findFpmSocket();
if (!$socket) {
    fail("No PHP-FPM socket found");
    sub("Is PHP-FPM installed and running?");
    cmd("sudo apt install php-fpm        # Debian/Ubuntu");
    cmd("sudo systemctl start php8.3-fpm # then start it (adjust version)");
    sub("If FPM is running but on a TCP port, edit /etc/qbixproxy/qbixproxy.json");
    sub("after setup and set \"socket\" to \"127.0.0.1:9000\" (or your port).");
    exit(1);
}

ok($socket);

// Warn if the socket file isn't readable by the likely service user
$serviceUser = detectServiceUser();
$socketPerms = @fileperms($socket);
if ($socketPerms !== false) {
    // Check group-write permission as a proxy for "our user can talk to FPM"
    // (This is a heuristic — full ACL checking would require posix_access())
    if (!($socketPerms & 0060)) {
        warn("Socket may not be readable by $serviceUser — check php-fpm pool config");
        sub("In the FPM pool .conf file, ensure: listen.owner = $serviceUser");
        sub("                                       listen.group = $serviceUser");
        sub("                                       listen.mode  = 0660");
    }
}
sub("service user: $serviceUser");

// ── Step 3: Detect web servers with PHP configs ───────────────────────────────
head("3. Web server configs");

$servers = detectWebServers();

// Apply --server filter if requested
if ($flagServer !== null) {
    if (!isset($servers[$flagServer])) {
        fail("--server=$flagServer: no $flagServer PHP configs found");
        sub("Detected servers: " . (empty($servers) ? "none" : implode(', ', array_keys($servers))));
        exit(1);
    }
    $servers = [$flagServer => $servers[$flagServer]];
    warn("--server=$flagServer: patching only $flagServer");
}

if (empty($servers)) {
    fail("No nginx / Apache / Caddy config with PHP found");
    warn("Is your web server installed and does it have a virtual host configured?");
    exit(1);
}

foreach ($servers as $name => $files) {
    ok(strtoupper($name) . " — " . count($files) . " PHP config(s) found");
    foreach ($files as $f) {
        $link = $f['link'];
        $real = $f['real'];
        $note = ($link !== $real) ? DIM . " → " . basename($real) . RESET : '';
        sub("  $link$note");
    }
}

if (count($servers) > 1) {
    warn("Multiple web servers detected — all will be patched");
    sub("Use --server=NAME to patch only one");
}

// ── Step 4: Auto-detect document root from config files ───────────────────────
//
// The document root is included in the qbixproxy.json config as DOCUMENT_ROOT,
// which PHP-FPM uses when evaluating SCRIPT_FILENAME for FastCGI requests.
// We try to read it from the web server config; if not found, we default to
// the common /var/www/html location.

$docRoot = '/var/www/html';
foreach ($servers as $name => $files) {
    $c    = (string) @file_get_contents($files[0]['real']);
    $root = null;
    if ($name === 'nginx'  && preg_match('/^\s*root\s+([^\s;]+)/m', $c, $m))  $root = $m[1];
    if ($name === 'apache' && preg_match('/DocumentRoot\s+([^\s<]+)/i', $c, $m)) $root = $m[1];
    if ($name === 'caddy'  && preg_match('/root\s+\*\s+([^\s\n]+)/i', $c, $m))   $root = $m[1];
    if ($root) { $docRoot = $root; break; }
}
sub("document_root: $docRoot");

// ── Step 5: Preview what will be created/changed ──────────────────────────────
head("4. Changes" . ($dryRun ? " (preview)" : ""));

// Files that will be written
$jsonContent = makeQbixproxyJson($socket, $docRoot);
$unitContent = makeSystemdUnit($serviceUser);

$exists = fn($p) => file_exists($p) ? DIM . ' (overwrite)' . RESET : DIM . ' (new)' . RESET;
go("/etc/qbixproxy/qbixproxy.json" . $exists('/etc/qbixproxy/qbixproxy.json'));
go("/etc/systemd/system/qbixproxy.service" . $exists('/etc/systemd/system/qbixproxy.service'));

// Config files that will be patched
foreach ($servers as $name => $files) {
    foreach ($files as $f) {
        $link = $f['link'];
        $real = $f['real'];
        $note = ($link !== $real) ? " (patches $real)" : '';
        go(strtoupper($name) . ": $link$note  →  patched  (.bak backup saved)");

        // Show the key lines changing (what gets removed, what gets added)
        $orig    = (string) @file_get_contents($real);
        $patched = match ($name) {
            'nginx'  => patchNginx($orig),
            'apache' => patchApache($orig),
            'caddy'  => patchCaddy($orig),
            default  => $orig,
        };
        showKeyChanges($name, $orig, $patched);
    }
}

// Check if qbixproxy is already running (service reload will be needed)
$svcActive = trim((string) shell_exec('systemctl is-active qbixproxy 2>/dev/null'));
if ($svcActive === 'active') {
    warn("qbixproxy is already running — will be restarted after config reload");
}

// ── dry-run exit ──────────────────────────────────────────────────────────────
if ($dryRun) {
    echo "\n";
    bar();
    if (!$isRoot) {
        echo BOLD . "  Preview complete. To apply these changes, run with sudo:" . RESET . "\n\n";
        cmd("sudo php " . basename(__FILE__) . ($flagServer ? " --server=$flagServer" : ""));
    } else {
        // Running as root with --dry-run
        echo BOLD . "  Preview complete. To apply, run without --dry-run:" . RESET . "\n\n";
        cmd("sudo php " . basename(__FILE__) . ($flagServer ? " --server=$flagServer" : ""));
    }
    echo "\n";
    bar();
    exit(0);
}

// ── Step 6: Confirm before applying (unless --yes was passed) ─────────────────
if (!$flagYes) {
    echo "\n";
    warn("About to patch your web server configs and start qbixproxy.");
    echo "       " . BOLD . "Continue? [Y/n]: " . RESET;
    $answer = strtolower(trim((string) fgets(STDIN)));
    if ($answer !== '' && $answer !== 'y' && $answer !== 'yes') {
        echo "\n";
        warn("Cancelled. No changes were made.");
        echo "       Run with --yes to skip this prompt.\n\n";
        exit(0);
    }
}

// ── Step 7: Write config files ────────────────────────────────────────────────
head("5. Writing config files");

writeFile('/etc/qbixproxy/qbixproxy.json',         $jsonContent) || exit(1);
writeFile('/etc/systemd/system/qbixproxy.service',  $unitContent) || exit(1);

// ── Step 8: Enable Apache modules + patch each server ─────────────────────────
head("6. Patching web server configs");

$anyFailed = false;

foreach ($servers as $name => $files) {
    // Apache needs three modules enabled before we can use ProxyPass + RequestHeader.
    // a2enmod enables them and creates symlinks in mods-enabled/. This is a no-op
    // if the module is already enabled. Only available on Debian/Ubuntu.
    if ($name === 'apache') {
        sub("Enabling Apache proxy modules...");
        foreach (['proxy', 'proxy_http', 'headers'] as $mod) {
            runCmd("a2enmod $mod 2>/dev/null", "  a2enmod $mod");
        }
    }

    foreach ($files as $f) {
        if (!patchAndApplyServer($name, $f, false)) {
            $anyFailed = true;
        }
    }
}

if ($anyFailed) {
    echo "\n";
    fail("One or more config patches failed. Qbix proxy service NOT started.");
    sub("Inspect the .failed files listed above, then re-run this script.");
    sub("Your original configs have been restored from .bak backups.");
    exit(1);
}

// ── Step 9: Start the qbixproxy service ──────────────────────────────────────
head("7. Starting qbixproxy service");

// daemon-reload tells systemd about the new service file we just wrote
runCmd('systemctl daemon-reload', 'systemctl daemon-reload') || exit(1);

// enable --now: enable (so it survives reboots) AND start in one command
runCmd('systemctl enable --now qbixproxy', 'qbixproxy enabled + started') || exit(1);

// ── Step 10: Reload each web server ──────────────────────────────────────────
head("8. Reloading web servers");

// "reload" sends SIGHUP — the web server re-reads its config without dropping
// existing connections. This is safer than "restart" for production servers.
foreach (array_keys($servers) as $name) {
    reloadWebServer($name);
}

// ─── Done ─────────────────────────────────────────────────────────────────────
echo "\n";
bar();
echo GREEN . BOLD . "  Done. " . RESET . "Qbix proxy is running on 127.0.0.1:8080.\n\n";

go("Health check:  curl http://127.0.0.1:8080/Q/health");
go("Metrics:       curl http://127.0.0.1:8080/Q/metrics");
go("Live logs:     journalctl -u qbixproxy -f");

echo "\n";
sub("To undo everything:");
foreach ($servers as $name => $files) {
    foreach ($files as $f) {
        $real = $f['real'];
        cmd("sudo cp $real.bak $real");
    }
}
cmd("sudo systemctl stop qbixproxy && sudo systemctl disable qbixproxy");
foreach (array_keys($servers) as $name) {
    $svc = match ($name) {
        'apache' => (is_file('/etc/debian_version') ? 'apache2' : 'httpd'),
        default  => $name,
    };
    cmd("sudo systemctl reload $svc");
}
echo "\n";
bar();
