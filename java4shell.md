# Java4Shell (CVE-2026-114938) — What it is and how Qbix proxy stops it

## The vulnerability

OpenJDK's Base64 decoder contains a handwritten AVX-512 VBMI assembly path for performance. A malformed short Base64 string — crafted to trigger the VBMI code path — causes a 62-byte out-of-bounds write past a heap buffer. This is a classic heap overflow: the attacker controls the bytes written, the offset is deterministic, and no Java version shipped before the patch contained a mitigation.

The attack surface is wide because Base64 is decoded *before* authentication. Any service that reads an `Authorization` header and passes it to the JVM's decoder is exploitable without credentials. Confirmed affected products include Keycloak, Jira, Confluence, Artifactory, Jenkins, Apache Struts, and Spring Boot. The researchers also demonstrated a client-side variant: a Java program that opens a TLS connection to a malicious server can be exploited by the server's response, even if the Java program itself exposes no open port.

## What Qbix proxy does

### Server-side (inbound) — automatic, no configuration needed

Stage 6 of the sanitization pipeline intercepts every `Authorization` header before it reaches the backend:

**`Authorization: Basic <b64>`** — The proxy decodes the Base64 payload with its own C decoder. Any invalid input (malformed characters, non-zero padding bits, missing colon separator in `user:password`) is rejected with HTTP 400. Valid credentials are re-encoded canonically and forwarded. The JVM's AVX-512 decoder never sees the client's bytes.

**`Authorization: Bearer <jwt>`** — If the token is a three-segment JWT (detected by the presence of exactly two dots), each segment is decoded as base64url and re-encoded without padding. The JVM decoder never sees the client's bytes. Opaque (non-JWT) Bearer tokens are passed through unchanged.

**All other schemes** — Passed through unchanged.

This is the same re-serialization principle used for php2shell: after the pipeline runs, the Authorization header contains bytes the proxy generated, not bytes the attacker sent. It is not a signature match and does not need to be updated when new exploit variants are discovered.

If you have Qbix proxy in front of your Java service, your inbound attack surface for Java4Shell is eliminated with no additional steps.

### Client-side (outbound) — 7-step sysadmin setup

When a Java program opens an outbound TLS connection to a malicious server, the malicious server controls what it sends back — including crafted Base64 that triggers the heap overflow. To cover this vector, run Qbix proxy as a TLS-intercepting forward proxy between the Java application and the network.

The approach uses `/etc/hosts` redirection and a local CA certificate. The Java app connects to the proxy (thinking it is connecting to the real host), the proxy holds a TLS session with both sides, normalizes the response, and forwards the clean bytes to the Java app. No kernel-level packet interception is required.

#### Step 1 — Generate a local CA certificate

Run this once on the machine where the Java service runs (or on a dedicated gateway machine if you are centralizing protection):

```bash
openssl req -x509 -newkey rsa:4096 \
  -keyout /etc/qbixproxy/ca.key \
  -out    /etc/qbixproxy/ca.crt \
  -days   3650 -nodes \
  -subj   "/CN=Qbix Proxy CA"
chmod 600 /etc/qbixproxy/ca.key
```

Keep `ca.key` private. Anyone who obtains it can forge certificates trusted by the JVMs you configure in step 2.

#### Step 2 — Install the CA in the JVM truststore

```bash
# Find the active JVM
JAVA_HOME=$(dirname $(dirname $(readlink -f $(which java))))

# Import the CA (default truststore password is "changeit")
keytool -importcert \
  -alias    qbixproxy-ca \
  -keystore "$JAVA_HOME/lib/security/cacerts" \
  -file     /etc/qbixproxy/ca.crt \
  -storepass changeit \
  -noprompt

# Verify
keytool -list -keystore "$JAVA_HOME/lib/security/cacerts" -storepass changeit | grep qbixproxy
```

If the Java service runs in a container, add this step to the container build.

#### Step 3 — Add /etc/hosts entries for known attack vectors

Redirect the hostnames most likely to serve exploit payloads to the proxy. For broad coverage, redirect all external hostnames you can enumerate; for surgical coverage, start with known vulnerable endpoints:

```
# /etc/hosts entries — point attack-vector hostnames to the proxy
127.0.0.1   auth.malicious-example.com
127.0.0.1   keycloak.internal            # if behind a separate Keycloak instance
```

For Java apps that connect to arbitrary external hosts (generic clients, SDKs, library code), use the explicit proxy settings in step 5 instead, which cover all outbound connections without enumeration.

#### Step 4 — Configure Qbix proxy for forward proxy mode

Add a `forward_proxy` section to your `qbixproxy.json`:

```json
{
  "forward_proxy": {
    "port": 8081,
    "ca_cert": "/etc/qbixproxy/ca.crt",
    "ca_key":  "/etc/qbixproxy/ca.key"
  },
  "backends": {
    ...
  }
}
```

The forward proxy listens on a separate port from the reverse proxy. It accepts `CONNECT` tunnel requests, terminates TLS using dynamically generated per-hostname certificates signed by the CA, normalizes Base64 in response headers and bodies, then relays the clean bytes to the Java client.

#### Step 5 — Set the proxy on the Java service

**Option A — environment variable (works for most JVM launchers):**

```bash
export HTTPS_PROXY=http://127.0.0.1:8081
export HTTP_PROXY=http://127.0.0.1:8081
```

**Option B — JVM system properties (more precise, overrides environment):**

```bash
java \
  -Dhttps.proxyHost=127.0.0.1 \
  -Dhttps.proxyPort=8081 \
  -Dhttp.proxyHost=127.0.0.1 \
  -Dhttp.proxyPort=8081 \
  -jar yourapp.jar
```

**Option C — iptables (covers all outbound connections, no app changes needed):**

```bash
# Redirect outbound HTTPS from the Java service's UID to the proxy
iptables -t nat -A OUTPUT \
  -m owner --uid-owner javauser \
  -p tcp --dport 443 \
  -j REDIRECT --to-port 8081

# Same for plain HTTP if in scope
iptables -t nat -A OUTPUT \
  -m owner --uid-owner javauser \
  -p tcp --dport 80 \
  -j REDIRECT --to-port 8081
```

The iptables option is the most complete: it covers connections opened by libraries or framework code that does not respect proxy environment variables.

#### Step 6 — Start Qbix proxy

```bash
./qbixproxy --config=/etc/qbixproxy/qbixproxy.json
```

Qbix proxy starts both the reverse proxy (for inbound) and the forward proxy (for outbound) from the same process and config file. The forward proxy port is separate from the reverse proxy port.

#### Step 7 — Verify

```bash
# Test that the proxy intercepts and normalizes a Base64 Authorization header
curl -x http://127.0.0.1:8081 \
  -H "Authorization: Basic $(echo -n 'user:pass' | base64)" \
  https://httpbin.org/headers

# Test that malformed Base64 is rejected (this should return 400)
curl -x http://127.0.0.1:8081 \
  -H "Authorization: Basic !!!invalid!!!" \
  https://httpbin.org/headers
```

For a more targeted check, connect to a local test server that echoes the headers it received and confirm the proxy's re-encoded value arrives, not the client's original.

## Certificate pinning

If the Java application pins the server's certificate or public key, TLS interception will fail — the proxy's dynamically generated certificate will not match the pinned value. There is no way to bypass a correct pin without modifying the application.

In practice, most Java services and framework clients do not pin certificates. Certificate pinning is an explicit opt-in that developers have to implement. The JVM's default behavior is to validate chain-of-trust only, which the proxy's CA satisfies. If you are unsure whether a specific application pins, check its source or test with a self-signed cert — a pinning failure produces a `SSLHandshakeException` with a clear message.

## Scope

The inbound Authorization normalization (stage 6) covers every Java service behind Qbix proxy automatically. The outbound forward proxy covers Java clients that open connections to external hosts. The two modes together close both attack vectors described in the Java4Shell research, including the samczsun client-side exploit.

Neither mode requires signatures or rule updates. Both operate on structural properties of Base64 — the same decode-and-re-encode invariant the proxy uses for multipart bodies against php2shell.
