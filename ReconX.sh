#!/usr/bin/env bash
set -uo pipefail

# ReconX - Bash Reconnaissance & Vulnerability Assessment Toolkit
# Authorized testing only: use against systems you own or have permission to assess.

TOOL_NAME="ReconX"
VERSION="1.0.0"
OUTPUT_DIR="${OUTPUT_DIR:-output}"

banner() {
  printf '\n'
  printf '  ____                                      \n'
  printf ' |  _ \\ ___  ___ ___  _ __ __  __           \n'
  printf ' | |_) / _ \\/ __/ _ \\|  _ \\\\ \\/ /           \n'
  printf ' |  _ <  __/ (_| (_) | | | |>  <            \n'
  printf ' |_| \\_\\___|\\___\\___/|_| |_/_/\\_\\           \n'
  printf '\n'
  printf '  %s v%s - Reconnaissance Toolkit\n' "$TOOL_NAME" "$VERSION"
  printf '  Discover. Analyze. Assess.\n\n'
}

usage() {
  banner
  cat <<'EOF'
Usage:
  ./ReconX.sh <target1> [target2 ...]
  ./ReconX.sh -f <targets-file>
  ./ReconX.sh --help

Examples:
  ./ReconX.sh example.com
  ./ReconX.sh 192.0.2.10 example.com
  ./ReconX.sh -f targets.txt

Options:
  -f FILE     Read one target per line (# comments and blank lines ignored)
  -h, --help  Show this help message

Only scan systems you own or have explicit permission to test.
EOF
}

log_message() {
  printf '[%s] [%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$TOOL_NAME" "$*" | tee -a "$OUTPUT_DIR/logs.txt"
}

log_vulnerability() {
  printf '[%s] [%s] POTENTIAL FINDING: %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$TOOL_NAME" "$*" | tee -a "$OUTPUT_DIR/vulnerabilities.txt"
}

require_tool() {
  command -v "$1" >/dev/null 2>&1 || {
    printf '[%s] Missing required tool: %s\n' "$TOOL_NAME" "$1" >&2
    return 1
  }
}

safe_target_name() {
  printf '%s' "$1" | sed 's/[^A-Za-z0-9._-]/_/g'
}

check_web_services() {
  local nmap_file="$1"
  grep -Eqi '(^|[[:space:]])(80|443|3000|8000|8080|8081|8443|8888|9000)/tcp[[:space:]]+open|Service: (http|https|http-alt|ssl/http)|Server: |Content-Type: text/html' "$nmap_file"
}

check_outdated_versions() {
  local nmap_file="$1" target="$2"

  if grep -Eq 'Apache/2\.(0|1|2)\.' "$nmap_file"; then
    log_vulnerability "Potentially outdated Apache version observed on $target; verify exact version and vendor support status. See $nmap_file."
  fi
  if grep -Eq 'OpenSSH [1-6]\.|OpenSSH 7\.[0-1]' "$nmap_file"; then
    log_vulnerability "Potentially outdated OpenSSH version observed on $target; verify exact version and vendor support status. See $nmap_file."
  fi
  if grep -Eq 'vsftpd 2\.3\.4' "$nmap_file"; then
    log_vulnerability "vsftpd 2.3.4 banner observed on $target; validate exposure and patch status. See $nmap_file."
  fi
  if grep -Eq 'MySQL 5\.0\.' "$nmap_file"; then
    log_vulnerability "Legacy MySQL 5.0 version banner observed on $target; verify exact version and support status. See $nmap_file."
  fi
}

parse_nikto_output() {
  local nikto_file="$1" target="$2"

  if grep -Eqi 'OSVDB|vulnerability|critical|high' "$nikto_file"; then
    log_vulnerability "Nikto reported possible findings for $target. Review $nikto_file manually; scanner output is not proof of exploitability."
  fi
  if grep -Fqi 'X-Frame-Options header is not present' "$nikto_file"; then
    log_vulnerability "Missing X-Frame-Options header reported for $target; assess clickjacking risk and CSP frame-ancestors. See $nikto_file."
  fi
  if grep -Fqi 'X-Content-Type-Options header is not set' "$nikto_file"; then
    log_vulnerability "Missing X-Content-Type-Options header reported for $target. See $nikto_file."
  fi
  if grep -Fqi 'HTTP TRACE method is active' "$nikto_file"; then
    log_vulnerability "HTTP TRACE method reported as enabled for $target; verify practical risk. See $nikto_file."
  fi
  if grep -Fqi 'phpinfo.php' "$nikto_file"; then
    log_vulnerability "Potential phpinfo.php exposure reported for $target; verify whether sensitive information is exposed. See $nikto_file."
  fi
}

perform_recon() {
  local target="$1"
  local target_name target_dir web_target
  target_name="$(safe_target_name "$target")"
  target_dir="$OUTPUT_DIR/$target_name"
  mkdir -p "$target_dir"

  log_message "Starting reconnaissance for: $target"

  if command -v ping >/dev/null 2>&1; then
    log_message "Running ping (failure does not stop other checks)..."
    ping -c 3 -W 2 "$target" >"$target_dir/ping.txt" 2>&1 || \
      log_message "Ping failed or ICMP is blocked for $target; continuing."
  fi

  if command -v nslookup >/dev/null 2>&1; then
    log_message "Running DNS lookup..."
    nslookup "$target" >"$target_dir/nslookup.txt" 2>&1 || log_message "DNS lookup failed for $target."
  fi

  if command -v whois >/dev/null 2>&1; then
    log_message "Running WHOIS lookup..."
    whois "$target" >"$target_dir/whois.txt" 2>&1 || log_message "WHOIS lookup failed for $target."
  fi

  if ! command -v nmap >/dev/null 2>&1; then
    log_message "Nmap is missing; cannot continue port/service scanning for $target."
    return 0
  fi

  log_message "Running Nmap full TCP-port, service/version, default-script and OS-detection scan..."
  nmap -sV -sC -O -T4 -p- "$target" >"$target_dir/nmap.txt" 2>&1 || \
    log_message "Nmap returned a non-zero status for $target; inspect $target_dir/nmap.txt."

  check_outdated_versions "$target_dir/nmap.txt" "$target"

  if check_web_services "$target_dir/nmap.txt"; then
    if command -v nikto >/dev/null 2>&1; then
      log_message "Likely HTTP(S) service detected; running Nikto..."
      web_target="$target"
      if [[ "$target" != http://* && "$target" != https://* ]]; then
        web_target="http://$target"
      fi
      nikto -h "$web_target" >"$target_dir/nikto.txt" 2>&1 || \
        log_message "Nikto returned a non-zero status for $target; inspect $target_dir/nikto.txt."
      parse_nikto_output "$target_dir/nikto.txt" "$target"
    else
      log_message "Nikto is not installed; skipping web scan for $target."
    fi
  else
    log_message "No likely web service detected in Nmap output for $target."
  fi

  log_message "Reconnaissance completed for $target. Results saved in $target_dir/"
}

main() {
  if [[ $# -lt 1 ]]; then usage; exit 1; fi
  if [[ "$1" == "-h" || "$1" == "--help" ]]; then usage; exit 0; fi

  local targets=()
  if [[ "$1" == "-f" ]]; then
    if [[ $# -ne 2 || ! -f "$2" ]]; then
      printf '[%s] Error: provide an existing targets file after -f.\n' "$TOOL_NAME" >&2
      usage
      exit 1
    fi
    while IFS= read -r line || [[ -n "$line" ]]; do
      line="${line%%#*}"
      line="$(printf '%s' "$line" | xargs)"
      [[ -z "$line" ]] && continue
      targets+=("$line")
    done < "$2"
  else
    targets=("$@")
  fi

  if [[ ${#targets[@]} -eq 0 ]]; then
    printf '[%s] No targets found.\n' "$TOOL_NAME" >&2
    exit 1
  fi

  for tool in grep sed xargs; do
    require_tool "$tool" || exit 1
  done

  banner
  log_message "Loaded ${#targets[@]} target(s)."
  for target in "${targets[@]}"; do
    perform_recon "$target"
  done
  log_message "All requested targets processed."
}

main "$@"
