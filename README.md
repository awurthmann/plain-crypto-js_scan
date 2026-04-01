# plain-crypto-js_scan

A lightweight incident-response script to detect potentially compromised Axios installations and the malicious `plain-crypto-js` dependency across:

- Local host systems
- Global npm installs
- Docker containers (running and stopped)
- Optional Docker images

---

## 🔍 What This Script Does

This script performs targeted filesystem and runtime checks to identify indicators of compromise related to the Axios supply chain incident.

### It Scans:

- Local (non-Docker) filesystem instances
- Global npm installs on the host
- Running and stopped Docker containers
- Optional local Docker images

### It Looks For:

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
- Scans **running and stopped containers**
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
