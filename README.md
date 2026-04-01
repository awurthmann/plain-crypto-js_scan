# plain-crypto-js_scan

A lightweight incident-response script to detect potentially compromised Axios installations and the malicious `plain-crypto-js` dependency across:

- Local host systems
- Global npm installs
- Docker containers (running and stopped)
- Optional Docker images

---

## 🔍 What This Script Does

This script performs targeted filesystem and runtime checks to identify indicators of compromise related to the Axios supply chain incident.

### It Scans

- Local (non-Docker) filesystem instances
- Global npm installs on the host
- Running and stopped Docker containers
- Optional local Docker images

### It Looks For

- `axios/package.json`
- Known bad Axios versions:
  - `1.14.1`
  - `0.30.4`
- `plain-crypto-js/package.json`
- Axios manifests referencing `plain-crypto-js` (possible tampering)

---

## ✅ Checks Performed

### Host

- `npm list axios`
- `npm list -g axios`
- Filesystem search for:
  - `node_modules/axios/package.json`
  - `node_modules/plain-crypto-js/package.json`

### Docker Containers

- Scans running and stopped containers
- Attempts:
  - `docker exec` scan (fast path)
  - Falls back to `docker export` if no shell (distroless, scratch, etc.)

### Docker Images (Optional)

- Disabled by default
- Can be enabled via environment variable

---

## 🚀 Usage

### Option 1: Clone and Run

```bash
git clone https://github.com/awurthmann/plain-crypto-js_scan.git
cd plain-crypto-js_scan

chmod +x ./plain-crypto-js_scan.sh
./plain-crypto-js_scan.sh
```

### Option 2: One-Liner

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/awurthmann/plain-crypto-js_scan/main/plain-crypto-js_scan.sh)"
```

---

## ⚙️ Optional Configuration

### Enable Docker Image Scanning

```bash
SCAN_DOCKER_IMAGES=1 ./plain-crypto-js_scan.sh
```

### Limit Host Scan Scope

```bash
HOST_ROOT="$HOME" ./plain-crypto-js_scan.sh
```

### Custom Temporary Directory Location

```bash
TMPDIR_BASE="/var/tmp" ./plain-crypto-js_scan.sh
```

---

## 🎨 Output

The script uses color-coded output for fast triage:

| Indicator | Meaning |
|----------|--------|
| 🔴 `[POTENTIAL HIT]` | Known bad Axios version detected |
| 🟣 `[plain-crypto-js]` | Malicious dependency present |
| 🟡 `[TAMPERED AXIOS?]` | Axios manifest references malicious dependency |
| 🔵 `[INFO]` | Informational messages |
| 🟢 `[OK]` | No findings |

---

## ⚠️ Important Notes

### Bash Return Codes

In the script:

- `0` = no findings
- `1` = one or more findings detected

This follows Bash conventions but may feel inverted from a human perspective.

---

## ⚠️ Caveats

This script is intended for triage, not full forensic validation.

Limitations include:

- Detects installed artifacts, not executed payloads
- May miss:
  - npm caches
  - tarballs
  - CI/CD build environments
  - ephemeral build layers
- May produce duplicate findings across scans
- Full root (`/`) scans can be slow and noisy

---

## 🧠 Recommended Next Steps (If Hits Found)

If any hits are detected:

- Assume compromise during install window
- Review:
  - CI/CD build logs
  - npm caches (`~/.npm`, `/root/.npm`)
  - Docker build pipelines
- Rotate:
  - credentials
  - API keys
  - tokens
- Rebuild:
  - containers
  - images
  - dependencies from trusted sources

---

## 📌 Why This Matters

The Axios supply chain incident demonstrates:

- Dependency trust is a real attack surface
- Build-time compromise can persist even if packages are removed later
- Minimal images can obscure inspection

This script helps quickly answer:

> “Where might we be exposed right now?”

---

## ⭐ Contributing

Pull requests, improvements, and additional detection logic are welcome.

