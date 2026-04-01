#!/usr/bin/env bash

###############################################################################
# Script Name: plain-crypto-js_scan.sh
#
# Description:
# This script scans:
#   - local, non Docker filesystem instances
#   - global npm installs on the host
#   - running and stopped Docker containers
#   - optional local Docker images
#
# It keeps the same logic and adds a clear separation between:
#   - host scan
#   - container scan
#   - image scan
#
# It looks for:
#   - axios/package.json
#   - bad Axios versions 1.14.1 and 0.30.4
#   - plain-crypto-js/package.json
#   - Axios manifests that reference plain-crypto-js
#
# Checks performed:
#   - host npm list axios
#   - host npm list -g axios
#   - host filesystem for node_modules/axios/package.json
#   - host filesystem for node_modules/plain-crypto-js/package.json
#   - running and stopped Docker containers
#   - Docker containers with no sh, using docker export fallback
#   - optional local Docker images
#
# Instructions:
#   Download plain-crypto-js_scan.sh
#   chmod +x ./plain-crypto-js_scan.sh
#   ./plain-crypto-js_scan.sh
#
#   OR
#
#   Copy and paste the line below into your shell:
#   bash -c "$(curl -fsSL https://raw.githubusercontent.com/awurthmann/plain-crypto-js_scan/main/plain-crypto-js_scan.sh)"
#
# Notes:
#   In Bash, return 0 usually means success.
#   In the helper below, "return $found_any" means:
#     0 = no hits found
#     1 = one or more hits found
#
# Caveats:
#   This is useful for triage, but it still has limits:
#   - It looks for installed files, not whether malicious code already executed.
#   - It may miss packages in caches, tarballs, build workspaces, or CI artifacts.
#   - It may produce duplicate hits if the same path is visible from multiple scans.
#   - Scanning all of / can be slow and noisy.
#
# Optional environment variables:
#   SCAN_DOCKER_IMAGES=1   Enable local Docker image scanning
#   HOST_ROOT=/path        Restrict the primary host scan root
#   TMPDIR_BASE=/path      Base directory for temporary extraction
#
# Examples:
#   ./plain-crypto-js_scan.sh
#   HOST_ROOT="$HOME" ./plain-crypto-js_scan.sh
#   SCAN_DOCKER_IMAGES=1 ./plain-crypto-js_scan.sh
###############################################################################

set -u

###############################################################################
# Configuration
###############################################################################

BAD_AXIOS_V1="1.14.1"
BAD_AXIOS_V2="0.30.4"

SCAN_DOCKER_IMAGES="${SCAN_DOCKER_IMAGES:-0}"
HOST_ROOT="${HOST_ROOT:-/}"
TMPDIR_BASE="${TMPDIR_BASE:-/tmp}"

###############################################################################
# Colors
# Uses ANSI colors when stdout is a terminal.
###############################################################################

if [ -t 1 ]; then
  C_RESET='\033[0m'
  C_BOLD='\033[1m'
  C_DIM='\033[2m'

  C_RED='\033[31m'
  C_GREEN='\033[32m'
  C_YELLOW='\033[33m'
  C_BLUE='\033[34m'
  C_MAGENTA='\033[35m'
  C_CYAN='\033[36m'
else
  C_RESET=''
  C_BOLD=''
  C_DIM=''

  C_RED=''
  C_GREEN=''
  C_YELLOW=''
  C_BLUE=''
  C_MAGENTA=''
  C_CYAN=''
fi

###############################################################################
# Logging helpers
###############################################################################

log_header() {
  echo
  echo "${C_BOLD}${C_CYAN}============================================================${C_RESET}"
  echo "${C_BOLD}${C_CYAN}$1${C_RESET}"
  echo "${C_BOLD}${C_CYAN}============================================================${C_RESET}"
}

log_info() {
  echo "${C_BLUE}[INFO]${C_RESET} $*"
}

log_warn() {
  echo "${C_YELLOW}[WARN]${C_RESET} $*"
}

log_error() {
  echo "${C_RED}[ERROR]${C_RESET} $*"
}

log_hit() {
  echo "${C_RED}[POTENTIAL HIT]${C_RESET} $*"
}

log_plain() {
  echo "${C_MAGENTA}[plain-crypto-js]${C_RESET} $*"
}

log_tampered() {
  echo "${C_YELLOW}[TAMPERED AXIOS?]${C_RESET} $*"
}

log_ok() {
  echo "${C_GREEN}[OK]${C_RESET} $*"
}

###############################################################################
# Utility helpers
###############################################################################

make_temp_dir() {
  mktemp -d "${TMPDIR_BASE%/}/scan-axios.XXXXXX"
}

# scan_root
#
# Scans a root path for:
#   - bad axios versions
#   - plain-crypto-js package manifests
#   - axios manifests that reference plain-crypto-js
#
# Arguments:
#   $1 = root path to scan
#   $2 = label to include in output
#
# Note on return code:
#   0 = no hits found
#   1 = one or more hits found
scan_root() {
  local root="$1"
  local label="$2"
  local found_any=0

  log_info "Scanning root: $root ($label)"

  local f version

  while read -r f; do
    [ -n "$f" ] || continue
    version=$(grep -m1 '"version"' "$f" 2>/dev/null | sed -E 's/.*"version":[[:space:]]*"([^"]+)".*/\1/')
    if [ "$version" = "$BAD_AXIOS_V1" ] || [ "$version" = "$BAD_AXIOS_V2" ]; then
      log_hit "[$label] $f -> $version"
      found_any=1
    fi

    if grep -q 'plain-crypto-js' "$f" 2>/dev/null; then
      log_tampered "[$label] $f"
      found_any=1
    fi
  done < <(find "$root" -path "*/node_modules/axios/package.json" 2>/dev/null)

  while read -r f; do
    [ -n "$f" ] || continue
    version=$(grep -m1 '"version"' "$f" 2>/dev/null | sed -E 's/.*"version":[[:space:]]*"([^"]+)".*/\1/')
    log_plain "[$label] $f -> $version"
    found_any=1
  done < <(find "$root" -path "*/node_modules/plain-crypto-js/package.json" 2>/dev/null)

  if [ "$found_any" -eq 0 ]; then
    log_ok "No hits found in $label"
  fi

  return "$found_any"
}

###############################################################################
# Host scan helpers
###############################################################################

# scan_host_npm_lists
#
# Checks npm package visibility from the host using npm itself.
# This is useful because some installations may be visible in npm output
# even if you are not scanning the same filesystem path directly.
scan_host_npm_lists() {
  log_header "HOST NPM LIST CHECKS"

  if command -v npm >/dev/null 2>&1; then
    log_info "npm detected on host"

    echo
    log_info "npm list axios"
    npm list axios 2>/dev/null || log_info "npm list axios returned no result or error"

    echo
    log_info "npm list -g axios"
    npm list -g axios 2>/dev/null || log_info "npm list -g axios returned no result or error"
  else
    log_info "npm not installed on host, skipping npm list checks"
  fi
}

# scan_host_filesystem
#
# Performs the primary host filesystem scan using HOST_ROOT.
# Default is /, which is comprehensive but can be slow and noisy.
scan_host_filesystem() {
  log_header "HOST FILESYSTEM SCAN"
  scan_root "$HOST_ROOT" "host"
}

# scan_common_host_locations
#
# Performs targeted scans of common locations where Node.js and npm content
# may exist. This can help catch things even when the primary host scan is
# restricted to a narrower HOST_ROOT.
scan_common_host_locations() {
  log_header "COMMON HOST LOCATIONS"

  local d
  for d in \
    "$HOME" \
    /usr/local/lib \
    /usr/lib \
    /opt \
    /var/lib \
    /root \
    /home
  do
    if [ -e "$d" ]; then
      scan_root "$d" "host:$d"
    fi
  done
}

###############################################################################
# Docker container scan helpers
###############################################################################

# scan_container_via_exec
#
# Attempts to scan a container by executing commands inside it using:
#   docker exec <container> sh -lc '...'
#
# This is fast and simple when sh exists in the container.
# It will fail for many minimal images such as distroless or scratch based
# images, in which case the caller should fall back to docker export.
scan_container_via_exec() {
  local cid="$1"

  docker exec "$cid" sh -lc '
    find / -path "*/node_modules/axios/package.json" 2>/dev/null | while read -r f; do
      version=$(grep -m1 "\"version\"" "$f" | sed -E "s/.*\"version\":[[:space:]]*\"([^\"]+)\".*/\1/")
      if [ "$version" = "1.14.1" ] || [ "$version" = "0.30.4" ]; then
        echo "[POTENTIAL HIT] [container] $f -> $version"
      fi
      if grep -q "plain-crypto-js" "$f" 2>/dev/null; then
        echo "[TAMPERED AXIOS?] [container] $f"
      fi
    done

    find / -path "*/node_modules/plain-crypto-js/package.json" 2>/dev/null | while read -r f; do
      version=$(grep -m1 "\"version\"" "$f" | sed -E "s/.*\"version\":[[:space:]]*\"([^\"]+)\".*/\1/")
      echo "[plain-crypto-js] [container] $f -> $version"
    done
  ' 2>&1
}

# render_exec_output
#
# Applies color to docker exec output lines that already contain our markers.
render_exec_output() {
  local line
  while IFS= read -r line; do
    case "$line" in
      "[POTENTIAL HIT]"*)
        echo "${C_RED}${line}${C_RESET}"
        ;;
      "[plain-crypto-js]"*)
        echo "${C_MAGENTA}${line}${C_RESET}"
        ;;
      "[TAMPERED AXIOS?]"*)
        echo "${C_YELLOW}${line}${C_RESET}"
        ;;
      *)
        echo "$line"
        ;;
    esac
  done
}

# scan_docker_containers
#
# Scans both running and stopped containers.
#
# Logic:
#   1. Try docker exec with sh
#   2. If that fails, fall back to:
#        docker export <container> | tar -C <tmpdir> -xf -
#      then scan the extracted filesystem locally
scan_docker_containers() {
  log_header "DOCKER CONTAINER SCAN"

  if ! command -v docker >/dev/null 2>&1; then
    log_info "docker not installed, skipping container scan"
    return 0
  fi

  docker ps -a --format '{{.ID}} {{.Image}} {{.Names}} {{.State}}' 2>/dev/null | while read -r cid image name state; do
    [ -n "${cid:-}" ] || continue

    echo
    echo "${C_BOLD}${C_CYAN}=== CONTAINER: $name ($image / $cid / $state) ===${C_RESET}"

    exec_output="$(scan_container_via_exec "$cid")"
    exec_rc=$?

    if [ $exec_rc -eq 0 ]; then
      if [ -n "$exec_output" ]; then
        printf '%s\n' "$exec_output" | render_exec_output
      else
        log_ok "No hits found via docker exec"
      fi
      continue
    fi

    log_warn "docker exec failed for $name ($cid)"
    printf '[WARN] %s\n' "$exec_output" | while IFS= read -r line; do
      echo "${C_YELLOW}${line}${C_RESET}"
    done
    log_info "Falling back to docker export"

    tmpdir="$(make_temp_dir)"
    if [ -z "$tmpdir" ] || [ ! -d "$tmpdir" ]; then
      log_error "Failed to create temporary directory"
      continue
    fi

    if ! docker export "$cid" | tar -C "$tmpdir" -xf - 2>/dev/null; then
      log_error "Failed to export container filesystem for $name ($cid)"
      rm -rf "$tmpdir"
      continue
    fi

    scan_root "$tmpdir" "container:$name:$cid"
    rm -rf "$tmpdir"
  done
}

###############################################################################
# Docker image scan helpers
###############################################################################

# scan_docker_images
#
# Optional image scanning. Disabled by default because image extraction can be
# slower and use more disk space.
#
# Enable with:
#   SCAN_DOCKER_IMAGES=1 ./plain-crypto-js_scan.sh
scan_docker_images() {
  log_header "DOCKER IMAGE SCAN"

  if ! command -v docker >/dev/null 2>&1; then
    log_info "docker not installed, skipping image scan"
    return 0
  fi

  if [ "$SCAN_DOCKER_IMAGES" != "1" ]; then
    log_info "Image scan disabled. Set SCAN_DOCKER_IMAGES=1 to enable."
    return 0
  fi

  docker images --format '{{.Repository}}:{{.Tag}} {{.ID}}' 2>/dev/null | while read -r image_ref image_id; do
    [ -n "${image_ref:-}" ] || continue

    echo
    echo "${C_BOLD}${C_CYAN}=== IMAGE: $image_ref ($image_id) ===${C_RESET}"

    tmp_container="$(docker create "$image_ref" 2>/dev/null)"
    if [ -z "$tmp_container" ]; then
      log_error "Failed to create temporary container from image $image_ref"
      continue
    fi

    tmpdir="$(make_temp_dir)"
    if [ -z "$tmpdir" ] || [ ! -d "$tmpdir" ]; then
      log_error "Failed to create temporary directory"
      docker rm "$tmp_container" >/dev/null 2>&1
      continue
    fi

    if ! docker export "$tmp_container" | tar -C "$tmpdir" -xf - 2>/dev/null; then
      log_error "Failed to export image filesystem for $image_ref"
      docker rm "$tmp_container" >/dev/null 2>&1
      rm -rf "$tmpdir"
      continue
    fi

    scan_root "$tmpdir" "image:$image_ref:$image_id"

    docker rm "$tmp_container" >/dev/null 2>&1
    rm -rf "$tmpdir"
  done
}

###############################################################################
# Main
###############################################################################

main() {
  log_header "AXIOS / plain-crypto-js SCAN"

  scan_host_npm_lists
  scan_host_filesystem
  scan_common_host_locations
  scan_docker_containers
  scan_docker_images

  echo
  log_info "Scan complete"
}

main "$@"
