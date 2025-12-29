# Docker Scan Script

A comprehensive Bash script for Docker container enumeration and vulnerability scanning, designed to identify escape vectors and common misconfigurations.

## Features
- **CVE Detection**: Targeted checks for:
  - **CVE-2025-9074**: Exposed unauthenticated Docker API (Docker Desktop).
  - **CVE-2022-0492**: cgroups release_agent escape.
  - **CVE-2019-5736**: runC binary overwrite.
  - **CVE-2024-21626**: runC process.cwd escape (FD leakage).
- **Host Discovery**: Multiple methods to find the host machine's IP (Gateway, DNS, /etc/resolv.conf).
- **Port Scanning**: Automated scanning of discovered host IPs for common services.
- **Privacy Focused**: No "port closed" noise, only actionable findings.
- **Summary Report**: Concise list of vulnerabilities at the end.

## Usage
```bash
chmod +x docker_scan.sh
./docker_scan.sh
```

## Credits
By Ikonw
