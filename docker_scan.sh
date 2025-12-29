#!/bin/bash
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'
COMMON_PORTS=(22 80 443 2375 2376 3306 6379 8080 9000)
SCANNED_IPS=()
FINDINGS=()
add_finding() {
    FINDINGS+=("$1")
}
is_scanned() {
    local ip=$1
    for i in "${SCANNED_IPS[@]}"; do
        if [[ "$i" == "$ip" ]]; then return 0; fi
    done
    return 1
}
scan_host() {
    local target=$1
    if [[ -z "$target" ]] || is_scanned "$target"; then return; fi
    SCANNED_IPS+=("$target")
    if [[ "$target" == *":"* ]]; then return; fi
    echo -e "${YELLOW}[*] Testing Host: $target${NC}"
    if ! command -v timeout >/dev/null 2>&1; then return; fi    
    for port in "${COMMON_PORTS[@]}"; do
        if (bash -c "timeout 0.3 bash -c 'cat < /dev/null > /dev/tcp/$target/$port'" 2>/dev/null); then
            echo -e "${RED}[!] PORT $port OPEN on $target${NC}"
            add_finding "Open port $port on $target"
            if [[ "$port" == "2375" || "$port" == "2376" ]]; then
                if command -v curl >/dev/null 2>&1; then
                    if curl -s -m 1 "http://$target:$port/version" | grep -q "ApiVersion"; then
                        echo -e "${RED}[!] CRITICAL: CVE-2025-9074 Detected! Unauthenticated Docker API at $target:$port${NC}"
                        add_finding "Vulnerable to CVE-2025-9074 (Exposed Docker API at $target:$port)"
                    fi
                fi
            fi
        fi
    done
}
echo -e "${BLUE}"
echo "    ____             __              _____                      "
echo "   / __ \____  _____/ /_____  _____ / ___/_________ _____        "
echo "  / / / / __ \/ ___/ //_/ _ \/ ___/ \__ \/ ___/ __ \/ __ \       "
echo " / /_/ / /_/ / /__/ ,< /  __/ /    ___/ / /__/ /_/ / / / /       "
echo "/_____/\____/\___/_/|_|\___/_/    /____/\___/\__,_/_/ /_/        "
echo -e "                                         By Ikonw${NC}"
echo -e "${BLUE}=================================================================${NC}"
if [ -f /.dockerenv ]; then
    echo -e "${GREEN}[+] Environment: Docker Container${NC}"
else
    echo -e "${YELLOW}[!] Environment: Unknown / Host${NC}"
fi
echo -e "Hostname: $(hostname)"
echo -e "User: $(whoami) ($(id -u))"
echo -e "\n${BLUE}--- [ Host Discovery & Port Scan ] ---${NC}"
GATEWAY=$(ip route 2>/dev/null | grep default | awk '{print $3}')
if [[ ! -z "$GATEWAY" ]]; then
    scan_host "$GATEWAY"
fi
SPECIAL_HOSTS=("host.docker.internal" "gateway.docker.internal")
for h in "${SPECIAL_HOSTS[@]}"; do
    IP=$(getent hosts "$h" 2>/dev/null | awk '{print $1}')
    if [[ ! -z "$IP" ]]; then
        scan_host "$IP"
    fi
done
if [ -f /etc/resolv.conf ]; then
    EXT_SERVER=$(grep "ExtServers:" /etc/resolv.conf | grep -oE "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+")
    if [[ ! -z "$EXT_SERVER" ]]; then
        scan_host "$EXT_SERVER"
    fi
fi
echo -e "\n${BLUE}--- [ Security Checks & CVEs ] ---${NC}"
if [ -S /var/run/docker.sock ]; then
    echo -e "${RED}[!] CRITICAL: /var/run/docker.sock EXPOSED${NC}"
    add_finding "Exposed docker.sock"
fi
if [ -f /sys/fs/cgroup/release_agent ] && [ -w /sys/fs/cgroup/release_agent ]; then
    echo -e "${RED}[!] CRITICAL: CVE-2022-0492 Detected! release_agent is WRITABLE${NC}"
    add_finding "Vulnerable to CVE-2022-0492 (cgroup release_agent escape)"
fi
if [ -w /proc/self/exe ]; then
    echo -e "${RED}[!] WARNING: CVE-2019-5736? /proc/self/exe is WRITABLE${NC}"
    add_finding "Potential CVE-2019-5736 (Writable /proc/self/exe)"
fi
if [ -d /proc/self/fd/7 ] || [ -d /proc/self/fd/8 ]; then
    echo -e "${RED}[!] WARNING: CVE-2024-21626? Leaked FDs detected in /proc/self/fd/${NC}"
    add_finding "Potential CVE-2024-21626 (Leaked FDs)"
fi
if grep -q "CapEff:\s*0000003fffffffff" /proc/self/status 2>/dev/null; then
    echo -e "${RED}[!] CRITICAL: PRIVILEGED CONTAINER (All Caps)${NC}"
    add_finding "Privileged mode enabled"
elif [ -d /dev ] && [ $(ls /dev 2>/dev/null | wc -l) -gt 100 ]; then
    echo -e "${RED}[!] HIGH: Likely Privileged Mode (High device count)${NC}"
    add_finding "Likely privileged mode"
fi
if command -v capsh >/dev/null 2>&1; then
    CAPS=$(capsh --print | grep Current)
    for cap in CAP_SYS_ADMIN CAP_SYS_PTRACE CAP_SYS_MODULE; do
        if echo "$CAPS" | grep -qi "$cap"; then
            echo -e "${RED}[!] WARNING: Dangerous Cap: $cap${NC}"
            add_finding "Dangerous capability: $cap"
        fi
    done
fi
if [ -r /etc/shadow ]; then
    echo -e "${RED}[!] WARNING: /etc/shadow is READABLE${NC}"
    add_finding "Readable /etc/shadow"
fi
echo -e "\n${BLUE}================[ Summary ]================${NC}"
if [ ${#FINDINGS[@]} -eq 0 ]; then
    echo -e "${GREEN}No obvious vulnerabilities found.${NC}"
else
    echo -e "${RED}Found ${#FINDINGS[@]} potential issue(s):${NC}"
    for f in "${FINDINGS[@]}"; do
        echo -e " - $f"
    done
fi
echo -e "${BLUE}===========================================${NC}"
