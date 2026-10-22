# ReconX

**ReconX** is a Bash-based reconnaissance and vulnerability-assessment helper for authorized security testing. It combines common network discovery utilities and stores raw scan output for manual review.

> **Authorized use only:** Scan only systems you own or have explicit written permission to assess. Scanning can generate noticeable traffic and trigger monitoring or service-provider policies.

## Features

- Ping reachability check (a failed ping does not stop other checks)
- DNS lookup with `nslookup`
- WHOIS lookup
- Nmap TCP port scan, service/version detection, default scripts, and OS detection
- Heuristic banner checks for selected legacy software versions
- Optional Nikto scan when likely web services are detected
- Timestamped ReconX logs and per-target output folders
- Single-target, multi-target, and targets-file input

## Requirements

Linux (such as Kali Linux or Ubuntu), Bash, and Nmap. Other utilities are used when installed.

Install common dependencies on Kali/Debian:

```bash
sudo apt update
sudo apt install -y bash nmap dnsutils whois nikto
```

## Installation

```bash
git clone https://github.com/YOUR-USERNAME/ReconX.git
cd ReconX
chmod +x ReconX.sh
```

Replace `YOUR-USERNAME` with your GitHub username.

## Usage

Scan one host:

```bash
./ReconX.sh example.com
```

Scan multiple authorized targets:

```bash
./ReconX.sh example.com 192.0.2.10
```

Read targets from a file:

```bash
./ReconX.sh -f targets.txt
```

Display help:

```bash
./ReconX.sh --help
```

Use `targets.example.txt` as a template. Blank lines and lines/comments beginning with `#` are ignored.

## Example terminal output

```text
  ReconX v1.0.0 - Reconnaissance Toolkit
  Discover. Analyze. Assess.

[2026-10-22 14:00:00] [ReconX] Loaded 1 target(s).
[2026-10-22 14:00:00] [ReconX] Starting reconnaissance for: example.com
[2026-10-22 14:00:00] [ReconX] Running DNS lookup...
```

## Output structure

Results are saved in `output/`:

```text
output/
├── logs.txt
├── vulnerabilities.txt
└── example.com/
    ├── ping.txt
    ├── nslookup.txt
    ├── whois.txt
    ├── nmap.txt
    └── nikto.txt
```

Files vary depending on installed tools and detected services. The `output/` directory is excluded from Git because results can contain sensitive information.

## Limitations and safe interpretation

- `-p-` scans all TCP ports and can take time. `-T4` may be noisy.
- Nmap OS detection (`-O`) may require elevated privileges.
- ICMP may be blocked even when a host is reachable.
- Version/banner matches are heuristics, not proof of a vulnerability. Vendors may backport security fixes without changing version strings.
- Nikto findings require manual validation; scanner output alone does not prove exploitability.
- If a target is supplied without a URL scheme, the optional Nikto check defaults to `http://`. Nmap input should normally be a hostname or IP address.
- ReconX is a learning/portfolio project, not a replacement for a scoped professional assessment.

## Roadmap

- Configurable quick/full scan profiles
- Target-scope allowlist and rate controls
- Consolidated Markdown/JSON reports
- Automated shell tests with mocked command output

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Do not commit secrets, customer data, or scan output from systems without permission.

## License

MIT. See [LICENSE](LICENSE).
