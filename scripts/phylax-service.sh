#!/bin/sh
# ==============================================================================
# Phylax (φύλαξ) — Universal Distro-Agnostic Service Manager
# One Job Principle (OJP): Lifecycle manager (install, start, stop, restart, status, reset, uninstall)
# Supports: systemd, OpenRC (Alpine/Gentoo), and SysVinit (Debian/RHEL legacy)
# POSIX-Compliant: Runs on sh, ash (BusyBox), dash, bash, zsh across all Linux distros
# ==============================================================================
set -eu

# Color constants (POSIX printf safe)
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    C_BOLD="\033[1m"
    C_GREEN="\033[0;32m"
    C_BLUE="\033[0;34m"
    C_YELLOW="\033[1;33m"
    C_RED="\033[0;31m"
    C_RESET="\033[0m"
else
    C_BOLD=""
    C_GREEN=""
    C_BLUE=""
    C_YELLOW=""
    C_RED=""
    C_RESET=""
fi

log_info() {
    printf "%bℹ️  %s%b\n" "${C_BLUE}" "$1" "${C_RESET}"
}

log_success() {
    printf "%b✅ %s%b\n" "${C_GREEN}" "$1" "${C_RESET}"
}

log_warn() {
    printf "%b⚠️  %s%b\n" "${C_YELLOW}" "$1" "${C_RESET}"
}

log_error() {
    printf "%b❌ %s%b\n" "${C_RED}" "$1" "${C_RESET}" >&2
}

# ------------------------------------------------------------------------------
# 1. Environment & Init System Detection
# ------------------------------------------------------------------------------
detect_init_system() {
    # If explicitly overridden by environment
    if [ -n "${PHYLAX_INIT_SYSTEM:-}" ]; then
        echo "${PHYLAX_INIT_SYSTEM}"
        return 0
    fi

    # Detect systemd (PID 1 is systemd or systemctl is available with active systemd)
    if [ -d /run/systemd/system ] || (command -v systemctl >/dev/null 2>&1 && systemctl is-system-running >/dev/null 2>&1); then
        echo "systemd"
        return 0
    fi

    # Detect OpenRC (standard on Alpine Linux, Gentoo)
    if command -v rc-service >/dev/null 2>&1 || [ -f /sbin/openrc-run ] || [ -d /run/openrc ]; then
        echo "openrc"
        return 0
    fi

    # Fallback to SysVinit if /etc/init.d exists
    if [ -d /etc/init.d ]; then
        echo "sysvinit"
        return 0
    fi

    echo "unknown"
}

# Find phylax binary location
find_phylax_bin() {
    if [ -n "${PHYLAX_BIN:-}" ]; then
        if [ -x "${PHYLAX_BIN}" ]; then
            echo "${PHYLAX_BIN}"
        fi
        return 0
    fi

    if command -v phylax >/dev/null 2>&1; then
        command -v phylax
        return 0
    fi

    for path in "/usr/local/bin/phylax" "/usr/bin/phylax" "${HOME}/.local/bin/phylax" "${HOME}/.cargo/bin/phylax"; do
        if [ -x "${path}" ]; then
            echo "${path}"
            return 0
        fi
    done

    echo ""
}

# Find or resolve configuration file location
find_phylax_config() {
    if [ -n "${PHYLAX_CONFIG:-}" ]; then
        echo "${PHYLAX_CONFIG}"
        return 0
    fi

    if [ "${USER_MODE:-0}" = "1" ]; then
        echo "${HOME}/.config/phylax/phylax.toml"
        return 0
    fi

    for path in "/etc/phylax/phylax.toml" "${HOME}/.config/phylax/phylax.toml"; do
        if [ -f "${path}" ]; then
            echo "${path}"
            return 0
        fi
    done

    # Default fallback target
    if [ "$(id -u)" -eq 0 ]; then
        echo "/etc/phylax/phylax.toml"
    else
        echo "${HOME}/.config/phylax/phylax.toml"
    fi
}

# Helper to run with sudo if not root
run_privileged() {
    if [ "$(id -u)" -eq 0 ]; then
        "$@"
    else
        if command -v sudo >/dev/null 2>&1; then
            sudo "$@"
        elif command -v doas >/dev/null 2>&1; then
            doas "$@"
        else
            log_error "Root privileges required for this action. Please run with sudo or as root."
            exit 1
        fi
    fi
}

# ------------------------------------------------------------------------------
# 2. Service Generation Templates
# ------------------------------------------------------------------------------

# Render systemd service unit (system-wide)
generate_systemd_unit() {
    _bin="$1"
    _cfg="$2"
    _user="${3:-phylax}"

    cat << EOF
[Unit]
Description=Phylax Sovereign Edge Defense & Reverse Proxy WAF
After=network.target network-online.target
Wants=network-online.target
Documentation=https://github.com/rmediatech/phylax

[Service]
Type=simple
User=${_user}
Group=${_user}
ExecStart=${_bin} serve --config ${_cfg}
Restart=always
RestartSec=3s
LimitNOFILE=65535
StandardOutput=journal
StandardError=journal

# Hardened Security Sandboxing
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log/phylax /etc/phylax
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
}

# Render systemd user service unit (per-user / non-root)
generate_systemd_user_unit() {
    _bin="$1"
    _cfg="$2"

    cat << EOF
[Unit]
Description=Phylax Sovereign Edge Defense & Reverse Proxy WAF
After=network.target
Documentation=https://github.com/rmediatech/phylax

[Service]
Type=simple
ExecStart=${_bin} serve --config ${_cfg}
Restart=always
RestartSec=3s
LimitNOFILE=65535
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=default.target
EOF
}

# Render OpenRC service script (Alpine Linux / Gentoo)
generate_openrc_script() {
    _bin="$1"
    _cfg="$2"
    _user="${3:-phylax}"

    cat << 'EOF'
#!/sbin/openrc-run
description="Phylax Sovereign Edge Defense & Reverse Proxy WAF"
description_checkconfig="Verify configuration file"

command="@BIN@"
command_args="serve --config @CFG@"
command_user="@USER@"
command_background="yes"
pidfile="/run/phylax.pid"

depend() {
    need net
    after firewall
}

checkconfig() {
    if [ ! -f "@CFG@" ]; then
        eerror "Configuration file @CFG@ not found!"
        return 1
    fi
}

start_pre() {
    checkconfig || return 1
    checkpath -d -m 0755 -o @USER@:@USER@ /var/log/phylax
}
EOF
}

# Render SysVinit LSB init script (Debian / RHEL fallback)
generate_sysvinit_script() {
    _bin="$1"
    _cfg="$2"
    _user="${3:-phylax}"

    cat << 'EOF'
#!/bin/sh
### BEGIN INIT INFO
# Provides:          phylax
# Required-Start:    $network $remote_fs $syslog
# Required-Stop:     $network $remote_fs $syslog
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Phylax Sovereign Edge Defense
# Description:       Sovereign 12-layer edge defense, honeypot tarpit, and WAF
### END INIT INFO

DAEMON="@BIN@"
CONFIG="@CFG@"
DAEMON_USER="@USER@"
PIDFILE="/var/run/phylax.pid"

case "$1" in
    start)
        echo "Starting phylax daemon..."
        start-stop-daemon --start --background --make-pidfile --pidfile "$PIDFILE" \
            --chuid "$DAEMON_USER" --exec "$DAEMON" -- serve --config "$CONFIG"
        ;;
    stop)
        echo "Stopping phylax daemon..."
        start-stop-daemon --stop --pidfile "$PIDFILE" --retry 5
        rm -f "$PIDFILE"
        ;;
    restart)
        $0 stop
        sleep 1
        $0 start
        ;;
    status)
        if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
            echo "phylax is running (pid $(cat "$PIDFILE"))."
            exit 0
        else
            echo "phylax is stopped."
            exit 3
        fi
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status}"
        exit 1
        ;;
esac
EOF
}

# ------------------------------------------------------------------------------
# 3. Actions Implementation
# ------------------------------------------------------------------------------

# ACTION: INSTALL
action_install() {
    _bin=$(find_phylax_bin)
    if [ -z "${_bin}" ]; then
        log_error "Phylax binary not found. Please compile or install it first (e.g. cargo install --features cli phylax)."
        exit 1
    fi

    _cfg=$(find_phylax_config)
    _cfg_dir=$(dirname "${_cfg}")

    log_info "Detected Phylax binary: ${_bin}"
    log_info "Configuration path:     ${_cfg}"

    # Generate config if it doesn't exist
    if [ ! -f "${_cfg}" ]; then
        log_info "Initializing template configuration at ${_cfg}..."
        if [ "${USER_MODE}" = "1" ]; then
            mkdir -p "${_cfg_dir}"
            "${_bin}" init --output "${_cfg}"
        else
            run_privileged mkdir -p "${_cfg_dir}"
            run_privileged "${_bin}" init --output "${_cfg}"
        fi
    fi

    _init_sys=$(detect_init_system)
    log_info "Detected Init System:    ${_init_sys}"

    if [ "${_init_sys}" = "systemd" ] && [ "${USER_MODE}" = "1" ]; then
        _unit_dir="${HOME}/.config/systemd/user"
        _unit_dest="${_unit_dir}/phylax.service"
        log_info "Service Mode:            systemd user instance"
        log_info "Generating systemd user unit at ${_unit_dest}..."
        mkdir -p "${_unit_dir}"
        generate_systemd_user_unit "${_bin}" "${_cfg}" > "${_unit_dest}"
        chmod 644 "${_unit_dest}"
        systemctl --user daemon-reload
        systemctl --user enable phylax.service
        log_success "systemd user service unit installed and enabled."
        log_info "Start service with: ${0} start --user"
        return 0
    fi

    # System-wide installation
    _service_user="phylax"
    if [ "$(id -u)" -eq 0 ]; then
        if ! id -u "${_service_user}" >/dev/null 2>&1; then
            log_info "Creating system service user '${_service_user}'..."
            if command -v useradd >/dev/null 2>&1; then
                useradd -r -s /sbin/nologin -M "${_service_user}" 2>/dev/null || true
            elif command -v adduser >/dev/null 2>&1; then
                # Alpine / BusyBox adduser
                adduser -S -D -H -s /sbin/nologin "${_service_user}" 2>/dev/null || true
            fi
        fi

        # Ensure log directory exists
        run_privileged mkdir -p /var/log/phylax
        run_privileged chown -R "${_service_user}:${_service_user}" /var/log/phylax "${_cfg_dir}" 2>/dev/null || true
    else
        _service_user="$(id -un)"
    fi

    case "${_init_sys}" in
        systemd)
            _unit_dest="/etc/systemd/system/phylax.service"
            log_info "Service Mode:            systemd system-wide"
            log_info "Generating systemd unit at ${_unit_dest}..."
            _tmp_unit=$(mktemp)
            generate_systemd_unit "${_bin}" "${_cfg}" "${_service_user}" > "${_tmp_unit}"
            run_privileged cp -f "${_tmp_unit}" "${_unit_dest}"
            rm -f "${_tmp_unit}"
            run_privileged chmod 644 "${_unit_dest}"
            run_privileged systemctl daemon-reload
            run_privileged systemctl enable phylax.service
            log_success "systemd service unit installed and enabled."
            log_info "Start service with: sudo ${0} start"
            ;;
        openrc)
            _rc_dest="/etc/init.d/phylax"
            log_info "Generating OpenRC script at ${_rc_dest}..."
            _tmp_rc=$(mktemp)
            generate_openrc_script "${_bin}" "${_cfg}" "${_service_user}" | \
                sed "s|@BIN@|${_bin}|g; s|@CFG@|${_cfg}|g; s|@USER@|${_service_user}|g" > "${_tmp_rc}"
            run_privileged cp -f "${_tmp_rc}" "${_rc_dest}"
            rm -f "${_tmp_rc}"
            run_privileged chmod 755 "${_rc_dest}"
            if command -v rc-update >/dev/null 2>&1; then
                run_privileged rc-update add phylax default
            fi
            log_success "OpenRC service installed and added to default runlevel."
            log_info "Start service with: sudo ${0} start"
            ;;
        sysvinit)
            _init_dest="/etc/init.d/phylax"
            log_info "Generating SysVinit script at ${_init_dest}..."
            _tmp_init=$(mktemp)
            generate_sysvinit_script "${_bin}" "${_cfg}" "${_service_user}" | \
                sed "s|@BIN@|${_bin}|g; s|@CFG@|${_cfg}|g; s|@USER@|${_service_user}|g" > "${_tmp_init}"
            run_privileged cp -f "${_tmp_init}" "${_init_dest}"
            rm -f "${_tmp_init}"
            run_privileged chmod 755 "${_init_dest}"
            log_success "SysVinit service installed at ${_init_dest}."
            log_info "Start service with: sudo ${0} start"
            ;;
        *)
            log_error "Could not automatically detect init system (systemd, openrc, or sysvinit)."
            log_info "You can run Phylax directly as a foreground or co-located process:"
            log_info "  ${_bin} serve --config ${_cfg}"
            exit 1
            ;;
    esac
}

# ACTION: START
action_start() {
    _init_sys=$(detect_init_system)
    if [ "${_init_sys}" = "systemd" ] && [ "${USER_MODE}" = "1" ]; then
        log_info "Starting Phylax user service (systemctl --user)..."
        systemctl --user start phylax.service
        log_success "Phylax user service started."
        return 0
    fi
    log_info "Starting Phylax service (${_init_sys})..."
    case "${_init_sys}" in
        systemd)
            run_privileged systemctl start phylax.service
            ;;
        openrc)
            run_privileged rc-service phylax start
            ;;
        sysvinit)
            run_privileged /etc/init.d/phylax start
            ;;
        *)
            log_error "Unsupported init system: ${_init_sys}"
            exit 1
            ;;
    esac
    log_success "Phylax service started."
}

# ACTION: STOP
action_stop() {
    _init_sys=$(detect_init_system)
    if [ "${_init_sys}" = "systemd" ] && [ "${USER_MODE}" = "1" ]; then
        log_info "Stopping Phylax user service (systemctl --user)..."
        systemctl --user stop phylax.service 2>/dev/null || true
        log_success "Phylax user service stopped."
        return 0
    fi
    log_info "Stopping Phylax service (${_init_sys})..."
    case "${_init_sys}" in
        systemd)
            run_privileged systemctl stop phylax.service 2>/dev/null || true
            ;;
        openrc)
            run_privileged rc-service phylax stop 2>/dev/null || true
            ;;
        sysvinit)
            run_privileged /etc/init.d/phylax stop 2>/dev/null || true
            ;;
        *)
            log_error "Unsupported init system: ${_init_sys}"
            exit 1
            ;;
    esac
    log_success "Phylax service stopped."
}

# ACTION: RESTART
action_restart() {
    _init_sys=$(detect_init_system)
    if [ "${_init_sys}" = "systemd" ] && [ "${USER_MODE}" = "1" ]; then
        log_info "Restarting Phylax user service (systemctl --user)..."
        systemctl --user restart phylax.service
        log_success "Phylax user service restarted."
        return 0
    fi
    log_info "Restarting Phylax service (${_init_sys})..."
    case "${_init_sys}" in
        systemd)
            run_privileged systemctl restart phylax.service
            ;;
        openrc)
            run_privileged rc-service phylax restart
            ;;
        sysvinit)
            run_privileged /etc/init.d/phylax restart
            ;;
        *)
            log_error "Unsupported init system: ${_init_sys}"
            exit 1
            ;;
    esac
    log_success "Phylax service restarted."
}

# ACTION: STATUS
action_status() {
    _init_sys=$(detect_init_system)
    if [ "${_init_sys}" = "systemd" ] && [ "${USER_MODE}" = "1" ]; then
        printf "%b=== Phylax Service Status (systemd --user) ===%b\n" "${C_BOLD}" "${C_RESET}"
        systemctl --user status phylax.service --no-pager || true
        return 0
    fi
    printf "%b=== Phylax Service Status (%s) ===%b\n" "${C_BOLD}" "${_init_sys}" "${C_RESET}"
    case "${_init_sys}" in
        systemd)
            systemctl status phylax.service --no-pager || true
            ;;
        openrc)
            rc-service phylax status || true
            ;;
        sysvinit)
            /etc/init.d/phylax status || true
            ;;
        *)
            log_error "Unsupported init system: ${_init_sys}"
            exit 1
            ;;
    esac
}

# ACTION: RESET
action_reset() {
    log_warn "Initiating Phylax Service Reset..."
    log_info "1. Stopping active service..."
    action_stop

    # Clear active log and state files if requested
    if [ "${USER_MODE}" = "1" ]; then
        if [ -d "${HOME}/.local/state/phylax" ]; then
            log_info "2. Truncating user log files..."
            find "${HOME}/.local/state/phylax" -type f -name "*.log" -exec truncate -s 0 {} + 2>/dev/null || true
        fi
    else
        if [ -d "/var/log/phylax" ]; then
            log_info "2. Truncating service log files..."
            run_privileged find /var/log/phylax -type f -name "*.log" -exec truncate -s 0 {} + 2>/dev/null || true
        fi
    fi

    # Test configuration validity
    _bin=$(find_phylax_bin)
    _cfg=$(find_phylax_config)
    if [ -n "${_bin}" ] && [ -f "${_cfg}" ]; then
        log_info "3. Testing configuration file syntax..."
        if "${_bin}" --version >/dev/null 2>&1; then
            log_success "Binary verification passed."
        fi
    fi

    log_info "4. Restarting service with pristine runtime state..."
    action_start
    log_success "Phylax service reset complete. Running cleanly."
}

# ACTION: UNINSTALL
action_uninstall() {
    log_warn "Uninstalling Phylax service..."
    action_stop

    _init_sys=$(detect_init_system)
    if [ "${_init_sys}" = "systemd" ] && [ "${USER_MODE}" = "1" ]; then
        _unit_dest="${HOME}/.config/systemd/user/phylax.service"
        if [ -f "${_unit_dest}" ]; then
            log_info "Disabling systemd user unit..."
            systemctl --user disable phylax.service 2>/dev/null || true
            rm -f "${_unit_dest}"
            systemctl --user daemon-reload
            log_success "Removed ${_unit_dest}."
        fi
        log_info "Note: Binary files and configuration templates were preserved."
        log_success "Phylax user service cleanly uninstalled."
        return 0
    fi

    case "${_init_sys}" in
        systemd)
            if [ -f "/etc/systemd/system/phylax.service" ]; then
                log_info "Disabling systemd unit..."
                run_privileged systemctl disable phylax.service 2>/dev/null || true
                run_privileged rm -f "/etc/systemd/system/phylax.service"
                run_privileged systemctl daemon-reload
                log_success "Removed /etc/systemd/system/phylax.service."
            fi
            ;;
        openrc)
            if [ -f "/etc/init.d/phylax" ]; then
                if command -v rc-update >/dev/null 2>&1; then
                    run_privileged rc-update del phylax default 2>/dev/null || true
                fi
                run_privileged rm -f "/etc/init.d/phylax"
                log_success "Removed /etc/init.d/phylax."
            fi
            ;;
        sysvinit)
            if [ -f "/etc/init.d/phylax" ]; then
                run_privileged rm -f "/etc/init.d/phylax"
                log_success "Removed /etc/init.d/phylax."
            fi
            ;;
    esac

    log_info "Note: Binary files and configuration templates were preserved."
    log_success "Phylax service cleanly uninstalled."
}

# ------------------------------------------------------------------------------
# 4. Command Router
# ------------------------------------------------------------------------------
show_help() {
    printf "%bUsage:%b %s <command> [--user|--system] [options]\n\n" "${C_BOLD}" "${C_RESET}" "$0"
    printf "%bCommands:%b\n" "${C_BOLD}" "${C_RESET}"
    printf "  %binstall%b     Generate and register service unit (systemd, openrc, or sysvinit)\n" "${C_GREEN}" "${C_RESET}"
    printf "  %bstart%b       Start the registered service\n" "${C_GREEN}" "${C_RESET}"
    printf "  %bstop%b        Stop the active service\n" "${C_GREEN}" "${C_RESET}"
    printf "  %brestart%b     Restart the service\n" "${C_GREEN}" "${C_RESET}"
    printf "  %bstatus%b      Check running state and recent logs\n" "${C_GREEN}" "${C_RESET}"
    printf "  %breset%b       Stop, flush logs/transient state, and restart cleanly\n" "${C_YELLOW}" "${C_RESET}"
    printf "  %buninstall%b   Stop, disable, and delete service unit files\n" "${C_RED}" "${C_RESET}"
    printf "\n"
    printf "%bOptions:%b\n" "${C_BOLD}" "${C_RESET}"
    printf "  --user             Manage service as systemd user unit (~/.config/systemd/user)\n"
    printf "  --system           Force system-wide installation (requires root or sudo)\n"
    printf "\n"
    printf "%bEnvironment Variables:%b\n" "${C_BOLD}" "${C_RESET}"
    printf "  PHYLAX_BIN         Explicit path to phylax binary\n"
    printf "  PHYLAX_CONFIG      Explicit path to phylax.toml configuration\n"
    printf "  PHYLAX_INIT_SYSTEM Force init system ('systemd', 'openrc', 'sysvinit')\n"
    printf "  PHYLAX_USER_MODE   Set to '1' to enforce systemd user mode\n"
    printf "  NO_COLOR           Disable colored terminal output\n\n"
}

USER_MODE=0
SYSTEM_MODE=0
COMMAND=""

for arg in "$@"; do
    case "$arg" in
        --user)
            USER_MODE=1
            ;;
        --system)
            SYSTEM_MODE=1
            ;;
        --source-only)
            return 0 2>/dev/null || exit 0
            ;;
        help|--help|-h)
            COMMAND="help"
            ;;
        *)
            if [ -z "${COMMAND}" ]; then
                COMMAND="$arg"
            fi
            ;;
    esac
done

if [ "${PHYLAX_SOURCE_ONLY:-}" = "1" ]; then
    return 0 2>/dev/null || exit 0
fi

# Respect PHYLAX_USER_MODE environment variable
if [ "${PHYLAX_USER_MODE:-0}" = "1" ]; then
    USER_MODE=1
fi

# Auto-detect user mode if running non-root and systemd is detected, unless --system explicitly forced
if [ "${USER_MODE}" = "0" ] && [ "${SYSTEM_MODE}" = "0" ] && [ "$(id -u)" -ne 0 ]; then
    _auto_init=$(detect_init_system)
    if [ "${_auto_init}" = "systemd" ]; then
        USER_MODE=1
    fi
fi

case "${COMMAND}" in
    install)
        action_install
        ;;
    start)
        action_start
        ;;
    stop)
        action_stop
        ;;
    restart)
        action_restart
        ;;
    status)
        action_status
        ;;
    reset)
        action_reset
        ;;
    uninstall)
        action_uninstall
        ;;
    help|"")
        show_help
        ;;
    *)
        log_error "Unknown command: ${COMMAND}"
        show_help
        exit 1
        ;;
esac
