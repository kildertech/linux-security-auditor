#!/usr/bin/env python3
"""
==========================================================
  Linux Security Auditor
  A comprehensive security audit & hardening tool
  Author: Kilder Joel
  GitHub: https://github.com/kildertech/linux-security-auditor
==========================================================
"""

import os
import sys
import subprocess
import datetime
import socket
import pwd
import grp
import stat
import json
import re


# ==========================================
#   COLORS (makes terminal output look pro)
# ==========================================

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    RESET = '\033[0m'


# ==========================================
#   BANNER
# ==========================================

def print_banner():
    banner = f"""
{Colors.RED}{Colors.BOLD}
  ██████╗ ███████╗ ██████╗    █████╗ ██╗   ██╗██████╗ ██╗████████╗
  ██╔════╝ ██╔════╝██╔════╝   ██╔══██╗██║   ██║██╔══██╗██║╚══██╔══╝
  ███████╗ █████╗  ██║        ███████║██║   ██║██║  ██║██║   ██║
  ╚════██║ ██╔══╝  ██║        ██╔══██║██║   ██║██║  ██║██║   ██║
  ███████║ ███████╗╚██████╗   ██║  ██║╚██████╔╝██████╔╝██║   ██║
  ╚══════╝ ╚══════╝ ╚═════╝   ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝   ╚═╝
{Colors.CYAN}  ⚡ Linux Security Auditor
{Colors.YELLOW}  Author: Kilder Joel
{Colors.RESET}"""
    print(banner)


# ==========================================
#   MAIN AUDITOR CLASS
# ==========================================

class SecurityAuditor:
    def __init__(self):
        self.results = []
        self.score = 100
        self.total_checks = 0
        self.passed = 0
        self.failed = 0
        self.warnings = 0

    def add_result(self, category, check, status, detail, fix=""):
        """Add a check result with category and fix suggestion"""
        self.results.append({
            'category': category,
            'check': check,
            'status': status,
            'detail': detail,
            'fix': fix
        })
        self.total_checks += 1

        if status == 'FAIL':
            self.score -= 5
            self.failed += 1
        elif status == 'PASS':
            self.passed += 1
        elif status == 'WARNING':
            self.score -= 2
            self.warnings += 1

    def run_cmd(self, command):
        """Run a shell command and return output"""
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=30
            )
            return result.stdout.strip(), result.stderr.strip(), result.returncode
        except subprocess.TimeoutExpired:
            return "", "Command timed out", 1
        except Exception as e:
            return "", str(e), 1

    # ==========================================
    #  1. USER & AUTHENTICATION CHECKS
    # ==========================================

    def check_users(self):
        cat = "👤 USER & AUTHENTICATION"
        print(f"\n{Colors.CYAN}[*] Checking Users & Authentication...{Colors.RESET}")

        # --- Check 1: Root login via SSH ---
        try:
            with open('/etc/ssh/sshd_config', 'r') as f:
                content = f.read()
                # Check for uncommented PermitRootLogin
                root_login = re.search(r'^PermitRootLogin\s+(\w+)', content, re.MULTILINE)
                if root_login and root_login.group(1).lower() == 'no':
                    self.add_result(cat, 'SSH Root Login', 'PASS',
                                    'Root login via SSH is disabled')
                else:
                    self.add_result(cat, 'SSH Root Login', 'FAIL',
                                    'Root login via SSH is ENABLED or not explicitly disabled',
                                    'Edit /etc/ssh/sshd_config → Set PermitRootLogin no → systemctl restart sshd')
        except FileNotFoundError:
            self.add_result(cat, 'SSH Root Login', 'WARNING',
                            'sshd_config not found')

        # --- Check 2: Empty passwords ---
        stdout, _, _ = self.run_cmd(['awk', '-F:', '($2 == "") {print $1}', '/etc/shadow'])
        if stdout:
            self.add_result(cat, 'Empty Passwords', 'FAIL',
                            f'Users with NO password: {stdout}',
                            'passwd <username> to set passwords')
        else:
            self.add_result(cat, 'Empty Passwords', 'PASS',
                            'No users with empty passwords')

        # --- Check 3: Users with UID 0 (root privileges) ---
        stdout, _, _ = self.run_cmd(['awk', '-F:', '($3 == 0) {print $1}', '/etc/passwd'])
        uid0_users = [u for u in stdout.split('\n') if u.strip()]
        if len(uid0_users) > 1:
            self.add_result(cat, 'Multiple UID 0 Users', 'FAIL',
                            f'Multiple root-level users found: {", ".join(uid0_users)}',
                            'Only root should have UID 0. Remove or change UID for others.')
        else:
            self.add_result(cat, 'Multiple UID 0 Users', 'PASS',
                            'Only root has UID 0')

        # --- Check 4: Users without passwords in shadow ---
        stdout, _, _ = self.run_cmd(['awk', '-F:', '($2 == "!" || $2 == "*") {print $1}', '/etc/shadow'])
        locked = stdout.split('\n') if stdout else []
        self.add_result(cat, 'Locked Accounts', 'INFO',
                        f'{len(locked)} system accounts are locked (normal)')

        # --- Check 5: Password aging policy ---
        stdout, _, _ = self.run_cmd(['grep', '-E', '^PASS_MAX_DAYS|^PASS_MIN_DAYS|^PASS_WARN_AGE', '/etc/login.defs'])
        if stdout:
            max_days = re.search(r'PASS_MAX_DAYS\s+(\d+)', stdout)
            if max_days and int(max_days.group(1)) <= 90:
                self.add_result(cat, 'Password Max Age', 'PASS',
                                f'Password expires within {max_days.group(1)} days')
            else:
                self.add_result(cat, 'Password Max Age', 'FAIL',
                                f'Password max age is too long or not set',
                                'Edit /etc/login.defs → Set PASS_MAX_DAYS 90')

        # --- Check 6: Sudo group members ---
        try:
            sudo_group = grp.getgrnam('sudo')
            sudo_users = sudo_group.gr_mem
            self.add_result(cat, 'Sudo Users', 'WARNING' if len(sudo_users) > 3 else 'INFO',
                            f'Sudo group members: {", ".join(sudo_users) if sudo_users else "None (root only)"}',
                            'Minimize sudo users. Review: getent group sudo')
        except KeyError:
            self.add_result(cat, 'Sudo Users', 'INFO', 'sudo group not found')

        # --- Check 7: Check for unauthorized sudoers files ---
        stdout, _, _ = self.run_cmd(['find', '/etc/sudoers.d/', '-type', 'f'])
        if stdout:
            files = stdout.split('\n')
            self.add_result(cat, 'Sudoers.d Files', 'WARNING',
                            f'Found {len(files)} custom sudoers files: {", ".join(files)}',
                            'Review each file for unnecessary privileges')
        else:
            self.add_result(cat, 'Sudoers.d Files', 'PASS',
                            'No custom sudoers files found')

        # --- Check 8: Login shells for system users ---
        stdout, _, _ = self.run_cmd(
            ['awk', '-F:', '($3 < 1000 && $7 != "/usr/sbin/nologin" && $7 != "/bin/false" && $1 != "root") {print $1":"$7}',
             '/etc/passwd'])
        if stdout:
            self.add_result(cat, 'System User Shells', 'FAIL',
                            f'System users with login shells: {stdout}',
                            'Set shell to /usr/sbin/nologin for system accounts')
        else:
            self.add_result(cat, 'System User Shells', 'PASS',
                            'All system users have restricted shells')

    # ==========================================
    #  2. NETWORK SECURITY CHECKS
    # ==========================================

    def check_network(self):
        cat = "🌐 NETWORK SECURITY"
        print(f"{Colors.CYAN}[*] Checking Network Security...{Colors.RESET}")

        # --- Check 1: Firewall ---
        stdout, _, rc = self.run_cmd(['ufw', 'status'])
        if 'active' in stdout.lower():
            self.add_result(cat, 'Firewall (UFW)', 'PASS', 'UFW is active')
        else:
            # Try iptables
            stdout2, _, _ = self.run_cmd(['iptables', '-L', '-n'])
            rules = [l for l in stdout2.split('\n') if l and not l.startswith('Chain') and not l.startswith('target')]
            if len(rules) > 0:
                self.add_result(cat, 'Firewall (iptables)', 'WARNING',
                                f'UFW inactive but iptables has {len(rules)} rules',
                                'Consider enabling UFW: sudo ufw enable')
            else:
                self.add_result(cat, 'Firewall', 'FAIL',
                                'NO FIREWALL ACTIVE!',
                                'sudo ufw enable && sudo ufw default deny incoming')

        # --- Check 2: Open ports ---
        stdout, _, _ = self.run_cmd(['ss', '-tuln'])
        lines = [l for l in stdout.split('\n')[1:] if l.strip()]
        open_ports = []
        for line in lines:
            parts = line.split()
            if len(parts) >= 5:
                addr = parts[4]
                open_ports.append(addr)

        dangerous_ports = {
            '21': 'FTP (unencrypted)',
            '23': 'TELNET (unencrypted!)',
            '25': 'SMTP',
            '53': 'DNS',
            '80': 'HTTP (unencrypted)',
            '110': 'POP3 (unencrypted)',
            '143': 'IMAP (unencrypted)',
            '445': 'SMB (common attack target)',
            '3306': 'MySQL',
            '5432': 'PostgreSQL',
            '6379': 'Redis (often unprotected)',
            '27017': 'MongoDB (often unprotected)',
            '8080': 'HTTP Alt',
            '8443': 'HTTPS Alt'
        }

        for addr in open_ports:
            port = addr.rsplit(':', 1)[-1] if ':' in addr else ''
            if port in dangerous_ports:
                self.add_result(cat, f'Open Port {port}', 'WARNING',
                                f'Port {port} is open: {dangerous_ports[port]}',
                                f'Close if not needed: sudo ufw deny {port}')

        self.add_result(cat, 'Total Open Ports', 'WARNING' if len(open_ports) > 10 else 'INFO',
                        f'{len(open_ports)} open ports detected')

        # --- Check 3: IP Forwarding ---
        stdout, _, _ = self.run_cmd(['sysctl', 'net.ipv4.ip_forward'])
        if '= 1' in stdout:
            self.add_result(cat, 'IP Forwarding', 'WARNING',
                            'IPv4 forwarding is ENABLED (potential routing risk)',
                            'Disable: sysctl -w net.ipv4.ip_forward=0')
        else:
            self.add_result(cat, 'IP Forwarding', 'PASS',
                            'IPv4 forwarding is disabled')

        # --- Check 4: TCP SYN Cookies (SYN flood protection) ---
        stdout, _, _ = self.run_cmd(['sysctl', 'net.ipv4.tcp_syncookies'])
        if '= 1' in stdout:
            self.add_result(cat, 'SYN Cookies', 'PASS',
                            'TCP SYN cookies enabled (SYN flood protection)')
        else:
            self.add_result(cat, 'SYN Cookies', 'FAIL',
                            'TCP SYN cookies DISABLED',
                            'sysctl -w net.ipv4.tcp_syncookies=1')

        # --- Check 5: ICMP Redirects ---
        stdout, _, _ = self.run_cmd(['sysctl', 'net.ipv4.conf.all.accept_redirects'])
        if '= 0' in stdout:
            self.add_result(cat, 'ICMP Redirects', 'PASS',
                            'ICMP redirects are rejected')
        else:
            self.add_result(cat, 'ICMP Redirects', 'FAIL',
                            'ICMP redirects are ACCEPTED (MiTM risk)',
                            'sysctl -w net.ipv4.conf.all.accept_redirects=0')

        # --- Check 6: Source Routing ---
        stdout, _, _ = self.run_cmd(['sysctl', 'net.ipv4.conf.all.accept_source_route'])
        if '= 0' in stdout:
            self.add_result(cat, 'Source Routing', 'PASS',
                            'Source routing is disabled')
        else:
            self.add_result(cat, 'Source Routing', 'FAIL',
                            'Source routing is ENABLED (spoofing risk)',
                            'sysctl -w net.ipv4.conf.all.accept_source_route=0')

        # --- Check 7: DNS nameservers ---
        try:
            with open('/etc/resolv.conf', 'r') as f:
                dns_servers = re.findall(r'nameserver\s+(\S+)', f.read())
                self.add_result(cat, 'DNS Servers', 'INFO',
                                f'DNS servers: {", ".join(dns_servers)}')
        except:
            pass

        # --- Check 8: Network interfaces in promiscuous mode ---
        stdout, _, _ = self.run_cmd(['ip', 'link', 'show'])
        if 'PROMISC' in stdout:
            self.add_result(cat, 'Promiscuous Mode', 'FAIL',
                            'Network interface in PROMISCUOUS mode (possible sniffer!)',
                            'Investigate: ip link show | grep PROMISC')
        else:
            self.add_result(cat, 'Promiscuous Mode', 'PASS',
                            'No interfaces in promiscuous mode')

    # ==========================================
    #  3. FILE SYSTEM SECURITY
    # ==========================================

    def check_filesystem(self):
        cat = "📂 FILE SYSTEM SECURITY"
        print(f"{Colors.CYAN}[*] Checking File System Security...{Colors.RESET}")

        # --- Check 1: /etc/shadow permissions ---
        critical_files = {
            '/etc/shadow': '-rw-r-----',
            '/etc/passwd': '-rw-r--r--',
            '/etc/group': '-rw-r--r--',
            '/etc/gshadow': '-rw-r-----',
            '/etc/ssh/sshd_config': '-rw-------',
        }

        for filepath, expected_perm in critical_files.items():
            if os.path.exists(filepath):
                stdout, _, _ = self.run_cmd(['ls', '-l', filepath])
                actual_perm = stdout.split()[0] if stdout else ''
                if actual_perm == expected_perm:
                    self.add_result(cat, f'Permissions: {filepath}', 'PASS',
                                    f'{actual_perm} (correct)')
                else:
                    self.add_result(cat, f'Permissions: {filepath}', 'FAIL',
                                    f'Got {actual_perm}, expected {expected_perm}',
                                    f'chmod {expected_perm} {filepath}')

        # --- Check 2: World-writable files ---
        stdout, _, _ = self.run_cmd(
            ['find', '/', '-xdev', '-type', 'f', '-perm', '-0002',
             '-not', '-path', '/proc/*', '-not', '-path', '/sys/*'])
        if stdout:
            ww_files = [f for f in stdout.split('\n') if f.strip()]
            self.add_result(cat, 'World-Writable Files', 'FAIL',
                            f'Found {len(ww_files)} world-writable files!',
                            'Review and fix: find / -xdev -type f -perm -0002')
        else:
            self.add_result(cat, 'World-Writable Files', 'PASS',
                            'No world-writable files found')

        # --- Check 3: World-writable directories without sticky bit ---
        stdout, _, _ = self.run_cmd(
            ['find', '/', '-xdev', '-type', 'd', '-perm', '-0002',
             '!', '-perm', '-1000', '-not', '-path', '/proc/*'])
        if stdout:
            ww_dirs = [d for d in stdout.split('\n') if d.strip()]
            self.add_result(cat, 'World-Writable Dirs (no sticky)', 'FAIL',
                            f'Found {len(ww_dirs)} unsafe directories!',
                            'Add sticky bit: chmod +t <directory>')
        else:
            self.add_result(cat, 'World-Writable Dirs', 'PASS',
                            'All world-writable dirs have sticky bit')

        # --- Check 4: SUID files ---
        stdout, _, _ = self.run_cmd(
            ['find', '/', '-xdev', '-perm', '-4000', '-type', 'f'])
        if stdout:
            suid_files = [f for f in stdout.split('\n') if f.strip()]
            known_suid = ['/usr/bin/sudo', '/usr/bin/passwd', '/usr/bin/chsh',
                          '/usr/bin/chfn', '/usr/bin/gpasswd', '/usr/bin/newgrp',
                          '/usr/bin/su', '/usr/bin/mount', '/usr/bin/umount',
                          '/usr/lib/openssh/ssh-keysign',
                          '/usr/lib/dbus-1.0/dbus-daemon-launch-helper']
            unknown_suid = [f for f in suid_files if f not in known_suid]

            if unknown_suid:
                self.add_result(cat, 'Suspicious SUID Files', 'WARNING',
                                f'Found {len(unknown_suid)} non-standard SUID files:\n   ' +
                                '\n   '.join(unknown_suid[:10]),
                                'Remove SUID if not needed: chmod u-s <file>')
            else:
                self.add_result(cat, 'SUID Files', 'PASS',
                                f'{len(suid_files)} SUID files, all appear standard')

        # --- Check 5: SGID files ---
        stdout, _, _ = self.run_cmd(
            ['find', '/', '-xdev', '-perm', '-2000', '-type', 'f'])
        if stdout:
            sgid_files = [f for f in stdout.split('\n') if f.strip()]
            self.add_result(cat, 'SGID Files', 'INFO',
                            f'Found {len(sgid_files)} SGID files. Review for unusual entries.')

        # --- Check 6: Unowned files ---
        stdout, _, _ = self.run_cmd(
            ['find', '/', '-xdev', '-nouser', '-o', '-nogroup'])
        if stdout:
            unowned = [f for f in stdout.split('\n') if f.strip()]
            self.add_result(cat, 'Unowned Files', 'FAIL',
                            f'Found {len(unowned)} files with no owner/group!',
                            'Assign ownership: chown root:root <file>')
        else:
            self.add_result(cat, 'Unowned Files', 'PASS',
                            'All files have valid owners')

        # --- Check 7: /tmp partition ---
        stdout, _, _ = self.run_cmd(['mount'])
        if '/tmp' in stdout:
            if 'noexec' in stdout.split('/tmp')[1].split('\n')[0]:
                self.add_result(cat, '/tmp noexec', 'PASS',
                                '/tmp is mounted with noexec')
            else:
                self.add_result(cat, '/tmp noexec', 'WARNING',
                                '/tmp is NOT mounted with noexec (malware risk)',
                                'Remount: mount -o remount,noexec /tmp')
        else:
            self.add_result(cat, '/tmp Partition', 'WARNING',
                            '/tmp is not a separate partition',
                            'Consider separate /tmp partition with noexec,nosuid')

    # ==========================================
    #  4. SSH HARDENING CHECKS
    # ==========================================

    def check_ssh(self):
        cat = "🔑 SSH HARDENING"
        print(f"{Colors.CYAN}[*] Checking SSH Configuration...{Colors.RESET}")

        try:
            with open('/etc/ssh/sshd_config', 'r') as f:
                content = f.read()
        except FileNotFoundError:
            self.add_result(cat, 'SSH Config', 'WARNING', 'SSH not installed')
            return

        # All SSH checks in one place
        ssh_checks = {
            'PermitRootLogin no': ('SSH Root Login', 'Root login should be disabled'),
            'PasswordAuthentication no': ('Password Auth', 'Password auth should be disabled (use keys)'),
            'PermitEmptyPasswords no': ('Empty Passwords SSH', 'Empty passwords must be rejected'),
            'X11Forwarding no': ('X11 Forwarding', 'X11 forwarding should be disabled'),
            'MaxAuthTries 3': ('Max Auth Tries', 'Should be 3 or less to prevent brute force'),
            'Protocol 2': ('SSH Protocol', 'Should use Protocol 2 only'),
            'AllowAgentForwarding no': ('Agent Forwarding', 'Should be disabled if not needed'),
            'ClientAliveInterval': ('Client Alive Interval', 'Should be set for idle timeout'),
            'LoginGraceTime 60': ('Login Grace Time', 'Should be 60 seconds or less'),
            'Banner /etc/issue.net': ('SSH Banner', 'Warning banner should be displayed'),
        }

        for setting, (name, description) in ssh_checks.items():
            key = setting.split()[0]
            # Search for the setting
            match = re.search(rf'^{key}\s+(.+)', content, re.MULTILINE)
            if match:
                value = match.group(1).strip()
                expected_value = setting.split(None, 1)[1] if ' ' in setting else None

                if expected_value and value.lower() == expected_value.lower():
                    self.add_result(cat, name, 'PASS', f'{key} = {value}')
                elif not expected_value:
                    self.add_result(cat, name, 'PASS', f'{key} is configured: {value}')
                else:
                    self.add_result(cat, name, 'FAIL',
                                    f'{key} = {value} (expected: {expected_value})',
                                    f'Edit /etc/ssh/sshd_config → {setting}')
            else:
                self.add_result(cat, name, 'FAIL',
                                f'{key} is not set! {description}',
                                f'Add to /etc/ssh/sshd_config: {setting}')

    # ==========================================
    #  5. SYSTEM & KERNEL CHECKS
    # ==========================================

    def check_system(self):
        cat = "⚙️ SYSTEM & KERNEL"
        print(f"{Colors.CYAN}[*] Checking System & Kernel...{Colors.RESET}")

        # --- Check 1: System updates ---
        stdout, _, _ = self.run_cmd(['apt', 'list', '--upgradable'])
        updates = [l for l in stdout.split('\n') if '/' in l]
        if updates:
            self.add_result(cat, 'System Updates', 'FAIL',
                            f'{len(updates)} packages need updating!',
                            'sudo apt update && sudo apt upgrade -y')
        else:
            self.add_result(cat, 'System Updates', 'PASS', 'System is up to date')

        # --- Check 2: Kernel version ---
        stdout, _, _ = self.run_cmd(['uname', '-r'])
        self.add_result(cat, 'Kernel Version', 'INFO', f'Running kernel: {stdout}')

        # --- Check 3: ASLR (Address Space Layout Randomization) ---
        stdout, _, _ = self.run_cmd(['sysctl', 'kernel.randomize_va_space'])
        if '= 2' in stdout:
            self.add_result(cat, 'ASLR', 'PASS',
                            'Full ASLR is enabled (kernel.randomize_va_space = 2)')
        else:
            self.add_result(cat, 'ASLR', 'FAIL',
                            'ASLR is not fully enabled!',
                            'sysctl -w kernel.randomize_va_space=2')

        # --- Check 4: Core dumps ---
        stdout, _, _ = self.run_cmd(['sysctl', 'fs.suid_dumpable'])
        if '= 0' in stdout:
            self.add_result(cat, 'Core Dumps (SUID)', 'PASS',
                            'SUID core dumps are disabled')
        else:
            self.add_result(cat, 'Core Dumps (SUID)', 'FAIL',
                            'SUID programs can dump core (info leak risk)',
                            'sysctl -w fs.suid_dumpable=0')

        # --- Check 5: dmesg restriction ---
        stdout, _, _ = self.run_cmd(['sysctl', 'kernel.dmesg_restrict'])
        if '= 1' in stdout:
            self.add_result(cat, 'dmesg Restriction', 'PASS',
                            'dmesg restricted to root only')
        else:
            self.add_result(cat, 'dmesg Restriction', 'FAIL',
                            'Any user can read dmesg (info leak)',
                            'sysctl -w kernel.dmesg_restrict=1')

        # --- Check 6: SELinux / AppArmor ---
        stdout_aa, _, rc_aa = self.run_cmd(['aa-status'])
        stdout_se, _, rc_se = self.run_cmd(['getenforce'])

        if rc_aa == 0 and 'profiles are loaded' in stdout_aa:
            self.add_result(cat, 'AppArmor', 'PASS', 'AppArmor is active')
        elif rc_se == 0 and 'Enforcing' in stdout_se:
            self.add_result(cat, 'SELinux', 'PASS', 'SELinux is enforcing')
        else:
            self.add_result(cat, 'MAC System', 'WARNING',
                            'No Mandatory Access Control (AppArmor/SELinux) detected',
                            'Install and enable AppArmor: apt install apparmor apparmor-utils')

        # --- Check 7: Automatic updates ---
        if os.path.exists('/etc/apt/apt.conf.d/20auto-upgrades'):
            with open('/etc/apt/apt.conf.d/20auto-upgrades', 'r') as f:
                content = f.read()
                if 'Unattended-Upgrade' in content and '"1"' in content:
                    self.add_result(cat, 'Auto Updates', 'PASS',
                                    'Unattended upgrades are enabled')
                else:
                    self.add_result(cat, 'Auto Updates', 'FAIL',
                                    'Automatic updates not fully configured',
                                    'apt install unattended-upgrades && dpkg-reconfigure unattended-upgrades')
        else:
            self.add_result(cat, 'Auto Updates', 'FAIL',
                            'Automatic updates not configured',
                            'apt install unattended-upgrades')

    # ==========================================
    #  6. LOGGING & AUDITING
    # ==========================================

    def check_logging(self):
        cat = "📝 LOGGING & AUDITING"
        print(f"{Colors.CYAN}[*] Checking Logging & Auditing...{Colors.RESET}")

        # --- Check 1: rsyslog ---
        stdout, _, _ = self.run_cmd(['systemctl', 'is-active', 'rsyslog'])
        if 'active' in stdout:
            self.add_result(cat, 'rsyslog', 'PASS', 'rsyslog is running')
        else:
            self.add_result(cat, 'rsyslog', 'FAIL',
                            'rsyslog is NOT running!',
                            'systemctl enable rsyslog && systemctl start rsyslog')

        # --- Check 2: auditd ---
        stdout, _, _ = self.run_cmd(['systemctl', 'is-active', 'auditd'])
        if 'active' in stdout:
            self.add_result(cat, 'auditd', 'PASS', 'Audit daemon is running')
        else:
            self.add_result(cat, 'auditd', 'FAIL',
                            'Audit daemon is NOT running!',
                            'apt install auditd && systemctl enable auditd && systemctl start auditd')

        # --- Check 3: Important log files exist ---
        log_files = ['/var/log/auth.log', '/var/log/syslog',
                     '/var/log/kern.log', '/var/log/faillog']
        for log in log_files:
            if os.path.exists(log):
                self.add_result(cat, f'Log: {log}', 'PASS', 'File exists')
            else:
                self.add_result(cat, f'Log: {log}', 'WARNING',
                                f'{log} not found',
                                'Check rsyslog configuration')

        # --- Check 4: Log permissions ---
        stdout, _, _ = self.run_cmd(['find', '/var/log', '-type', 'f', '-perm', '-o+w'])
        if stdout:
            self.add_result(cat, 'Log Permissions', 'FAIL',
                            'Some log files are world-writable!',
                            'chmod o-w /var/log/*')
        else:
            self.add_result(cat, 'Log Permissions', 'PASS',
                            'Log files are not world-writable')

        # --- Check 5: Failed login attempts ---
        stdout, _, _ = self.run_cmd(['grep', '-c', 'Failed password', '/var/log/auth.log'])
        try:
            failed_count = int(stdout.strip())
            if failed_count > 100:
                self.add_result(cat, 'Failed Logins', 'FAIL',
                                f'{failed_count} failed login attempts in auth.log!',
                                'Consider installing fail2ban')
            elif failed_count > 20:
                self.add_result(cat, 'Failed Logins', 'WARNING',
                                f'{failed_count} failed login attempts detected')
            else:
                self.add_result(cat, 'Failed Logins', 'PASS',
                                f'Only {failed_count} failed login attempts')
        except:
            self.add_result(cat, 'Failed Logins', 'INFO',
                            'Could not parse auth.log')

    # ==========================================
    #  7. MALWARE & ROOTKIT CHECKS
    # ==========================================

    def check_malware(self):
        cat = "🦠 MALWARE & ROOTKIT"
        print(f"{Colors.CYAN}[*] Checking for Malware & Rootkits...{Colors.RESET}")

        # --- Check 1: Suspicious cron jobs ---
        cron_dirs = ['/etc/cron.d/', '/etc/cron.daily/', '/etc/cron.hourly/',
                     '/etc/cron.weekly/', '/etc/cron.monthly/', '/var/spool/cron/']

        suspicious_cron = []
        for cron_dir in cron_dirs:
            if os.path.exists(cron_dir):
                for f in os.listdir(cron_dir):
                    filepath = os.path.join(cron_dir, f)
                    if os.path.isfile(filepath):
                        try:
                            with open(filepath, 'r') as fh:
                                content = fh.read()
                                # Look for suspicious patterns
                                sus_patterns = ['wget ', 'curl ', 'nc ', 'ncat ',
                                                '/dev/tcp/', 'base64', 'eval ',
                                                'python -c', 'bash -i', '/tmp/']
                                for pattern in sus_patterns:
                                    if pattern in content:
                                        suspicious_cron.append(f'{filepath} → contains "{pattern}"')
                        except:
                            pass

        if suspicious_cron:
            self.add_result(cat, 'Suspicious Cron Jobs', 'FAIL',
                            'Found suspicious cron entries:\n   ' +
                            '\n   '.join(suspicious_cron[:5]),
                            'Investigate and remove unauthorized cron jobs')
        else:
            self.add_result(cat, 'Cron Jobs', 'PASS',
                            'No suspicious patterns found in cron jobs')

        # --- Check 2: Hidden files in common directories ---
        stdout, _, _ = self.run_cmd(
            ['find', '/tmp', '/var/tmp', '/dev/shm', '-name', '.*', '-type', 'f'])
        if stdout:
            hidden = stdout.split('\n')
            self.add_result(cat, 'Hidden Files in /tmp', 'WARNING',
                            f'Found {len(hidden)} hidden files in temp directories',
                            'Review: find /tmp /var/tmp /dev/shm -name ".*" -type f')
        else:
            self.add_result(cat, 'Hidden Files in /tmp', 'PASS',
                            'No hidden files in temp directories')

        # --- Check 3: Running processes with no binary ---
        stdout, _, _ = self.run_cmd(['ps', 'aux'])
        deleted_procs = [l for l in stdout.split('\n') if '(deleted)' in l]
        if deleted_procs:
            self.add_result(cat, 'Deleted Binary Processes', 'FAIL',
                            f'{len(deleted_procs)} processes running from deleted binaries!',
                            'Investigate these processes immediately')
        else:
            self.add_result(cat, 'Deleted Binary Processes', 'PASS',
                            'No processes running from deleted binaries')

        # --- Check 4: Listening on unusual ports ---
        stdout, _, _ = self.run_cmd(['ss', '-tlnp'])
        backdoor_ports = ['4444', '5555', '1337', '31337', '12345',
                          '6666', '6667', '9999', '1234']
        for line in stdout.split('\n'):
            for port in backdoor_ports:
                if f':{port}' in line:
                    self.add_result(cat, f'Suspicious Port {port}', 'FAIL',
                                    f'Known backdoor port {port} is LISTENING!\n   {line.strip()}',
                                    f'Investigate immediately: ss -tlnp | grep {port}')

        # --- Check 5: Check for common rootkit files ---
        rootkit_files = [
            '/usr/bin/sourcemask', '/usr/bin/Xorg',
            '/tmp/.ICE-unix/..', '/tmp/.X11-unix/..',
            '/dev/.udev/rules.d', '/etc/ld.so.preload'
        ]
        for rk_file in rootkit_files:
            if os.path.exists(rk_file):
                self.add_result(cat, f'Rootkit Indicator: {rk_file}', 'FAIL',
                                f'Suspicious file found: {rk_file}',
                                'Run rkhunter or chkrootkit for full scan')

        # --- Check 6: Check /etc/ld.so.preload ---
        if os.path.exists('/etc/ld.so.preload'):
            with open('/etc/ld.so.preload', 'r') as f:
                content = f.read().strip()
                if content:
                    self.add_result(cat, 'ld.so.preload', 'FAIL',
                                    f'ld.so.preload contains entries (possible rootkit): {content}',
                                    'Investigate immediately!')
                else:
                    self.add_result(cat, 'ld.so.preload', 'PASS',
                                    'ld.so.preload is empty')
        else:
            self.add_result(cat, 'ld.so.preload', 'PASS',
                            'ld.so.preload does not exist')

        # --- Check 7: rkhunter / chkrootkit installed? ---
        _, _, rc1 = self.run_cmd(['which', 'rkhunter'])
        _, _, rc2 = self.run_cmd(['which', 'chkrootkit'])
        if rc1 != 0 and rc2 != 0:
            self.add_result(cat, 'Rootkit Scanner', 'WARNING',
                            'No rootkit scanner installed!',
                            'apt install rkhunter chkrootkit')
        else:
            self.add_result(cat, 'Rootkit Scanner', 'PASS',
                            'Rootkit scanner is installed')

    # ==========================================
    #  8. SERVICE HARDENING
    # ==========================================

    def check_services(self):
        cat = "🔧 SERVICE HARDENING"
        print(f"{Colors.CYAN}[*] Checking Services...{Colors.RESET}")

        # Check for unnecessary services
        dangerous_services = {
            'telnet': 'Telnet is unencrypted - use SSH instead',
            'rsh': 'Remote shell is insecure',
            'rlogin': 'Remote login is insecure',
            'rexec': 'Remote exec is insecure',
            'ftp': 'FTP is unencrypted - use SFTP instead',
            'vsftpd': 'FTP service - use SFTP if possible',
            'avahi-daemon': 'mDNS - disable if not needed',
            'cups': 'Print service - disable if not needed',
            'bluetooth': 'Bluetooth - disable if not needed on server',
        }

        for service, warning in dangerous_services.items():
            stdout, _, _ = self.run_cmd(['systemctl', 'is-active', service])
            if 'active' in stdout and 'inactive' not in stdout:
                self.add_result(cat, f'Service: {service}', 'WARNING',
                                f'{service} is running! {warning}',
                                f'systemctl disable {service} && systemctl stop {service}')

        # Check fail2ban
        stdout, _, _ = self.run_cmd(['systemctl', 'is-active', 'fail2ban'])
        if 'active' in stdout:
            self.add_result(cat, 'fail2ban', 'PASS', 'fail2ban is running')
        else:
            self.add_result(cat, 'fail2ban', 'FAIL',
                            'fail2ban is NOT running (brute force protection)',
                            'apt install fail2ban && systemctl enable fail2ban')

    # ==========================================
    #   GENERATE REPORT
    # ==========================================

    def generate_report(self):
        """Generate the final security report"""
        final_score = max(self.score, 0)

        print(f"\n{'=' * 70}")
        print(f"{Colors.BOLD}{Colors.CYAN}")
        print(f"  ██████╗ ███████╗██████╗  ██████╗ ██████╗ ████████╗")
        print(f"  ██╔══██╗██╔════╝██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝")
        print(f"  ██████╔╝█████╗  ██████╔╝██║   ██║██████╔╝   ██║   ")
        print(f"  ██╔══██╗██╔══╝  ██╔═══╝ ██║   ██║██╔══██╗   ██║   ")
        print(f"  ██║  ██║███████╗██║     ╚██████╔╝██║  ██║   ██║   ")
        print(f"  ╚═╝  ╚═╝╚══════╝╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ")
        print(f"{Colors.RESET}")
        print(f"  📅 Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"  💻 Host: {os.uname().nodename}")
        print(f"  🐧 OS:   {os.uname().sysname} {os.uname().release}")
        print(f"{'=' * 70}")

        # Group results by category
        categories = {}
        for r in self.results:
            cat = r['category']
            if cat not in categories:
                categories[cat] = []
            categories[cat].append(r)

        for cat, results in categories.items():
            print(f"\n{Colors.BOLD}{Colors.MAGENTA}{'─' * 70}")
            print(f"  {cat}")
            print(f"{'─' * 70}{Colors.RESET}")

            for r in results:
                icons = {
                    'PASS': f'{Colors.GREEN}✅ [PASS]',
                    'FAIL': f'{Colors.RED}❌ [FAIL]',
                    'WARNING': f'{Colors.YELLOW}⚠️  [WARN]',
                    'INFO': f'{Colors.BLUE}ℹ️  [INFO]'
                }
                icon = icons.get(r['status'], '?')
                print(f"\n  {icon}{Colors.RESET} {Colors.BOLD}{r['check']}{Colors.RESET}")
                print(f"       {r['detail']}")
                if r['fix']:
                    print(f"       {Colors.YELLOW}💡 FIX: {r['fix']}{Colors.RESET}")

        # === SUMMARY ===
        print(f"\n{'=' * 70}")
        print(f"{Colors.BOLD}  📊 SUMMARY{Colors.RESET}")
        print(f"{'=' * 70}")
        print(f"  Total Checks:  {self.total_checks}")
        print(f"  {Colors.GREEN}Passed:  {self.passed}{Colors.RESET}")
        print(f"  {Colors.RED}Failed:  {self.failed}{Colors.RESET}")
        print(f"  {Colors.YELLOW}Warnings: {self.warnings}{Colors.RESET}")

        # Score bar
        print(f"\n  {'=' * 50}")
        bar_length = 40
        filled = int(bar_length * final_score / 100)
        bar_color = Colors.GREEN if final_score >= 80 else Colors.YELLOW if final_score >= 50 else Colors.RED
        bar = f"{'█' * filled}{'░' * (bar_length - filled)}"
        print(f"  {bar_color}  [{bar}] {final_score}/100{Colors.RESET}")

        if final_score >= 80:
            grade = f"{Colors.GREEN}  ✅ GRADE: GOOD - System is reasonably hardened{Colors.RESET}"
        elif final_score >= 60:
            grade = f"{Colors.YELLOW}  ⚠️  GRADE: FAIR - Several issues need attention{Colors.RESET}"
        elif final_score >= 40:
            grade = f"{Colors.RED}  ❌ GRADE: POOR - Significant hardening needed!{Colors.RESET}"
        else:
            grade = f"{Colors.RED}{Colors.BOLD}  🚨 GRADE: CRITICAL - System is vulnerable!{Colors.RESET}"

        print(f"\n{grade}")
        print(f"\n{'=' * 70}\n")

    # ==========================================
    #   EXPORT REPORT TO FILE
    # ==========================================

    def export_report(self, filename="reports/audit_report.json"):
        """Export results to JSON file"""
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        report = {
            'date': datetime.datetime.now().isoformat(),
            'hostname': os.uname().nodename,
            'kernel': os.uname().release,
            'score': max(self.score, 0),
            'total_checks': self.total_checks,
            'passed': self.passed,
            'failed': self.failed,
            'warnings': self.warnings,
            'results': self.results
        }
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"{Colors.GREEN}[+] Report saved to {filename}{Colors.RESET}")


# ==========================================
#   MAIN
# ==========================================

def main():
    if os.geteuid() != 0:
        print(f"{Colors.RED}⚠️  Run as root: sudo python3 auditor.py{Colors.RESET}")
        sys.exit(1)

    print_banner()

    auditor = SecurityAuditor()

    print(f"\n{Colors.BOLD}{Colors.RED}⚡ STARTING AGGRESSIVE SECURITY AUDIT...{Colors.RESET}\n")

    # Run ALL checks
    auditor.check_users()
    auditor.check_network()
    auditor.check_filesystem()
    auditor.check_ssh()
    auditor.check_system()
    auditor.check_logging()
    auditor.check_malware()
    auditor.check_services()

    # Generate report
    auditor.generate_report()

    # Export to JSON
    auditor.export_report()


if __name__ == '__main__':
    main()
