#!/usr/bin/env bash
# =============================================================================
#  install-ejbca.sh  -  EJBCA v2 installer (patched EJBCA-CE + HSM add-ons)
# =============================================================================
#  Target : Ubuntu 22.04 LTS (x86_64), offline
#  DB     : local MariaDB
#  AppSrv : WildFly (HTTP / HTTPS on separate ports)
#  Ref    : https://docs.keyfactor.com/ejbca-software/latest/installation
#
#  USAGE
#    sudo ./install-ejbca.sh --config FILE --mode MODE [--addon NAME]... [--yes]
#
#    --config FILE      ejbca-install.conf (see ejbca-install.conf.sample)   [required]
#    --mode MODE        fresh            new host, new database, new ManagementCA
#                       upgrade-from-7x  new host, database imported from a 7.x
#                                        instance (UPGRADE_DB_DUMP), its TLS
#                                        keystores reused; EJBCA's standard
#                                        upgrade and post-upgrade run here.
#                                        Then run each add-on's
#                                        --mode migrate-from-7x.          [required]
#    --addon NAME       add-on shipped in the EJBCA source (addons/NAME/) to
#                       install, e.g. ed25519 (repeat for several add-ons). Its
#                       addons/NAME/install-NAME.sh runs at the hook points.  [optional]
#    --yes              do not ask for confirmation after the plan
#
#  The script never uses the network. Everything comes from BUNDLE_DIR
#  (see fetch-bundle.sh). It never guesses: missing config values, a non-empty
#  target (existing WildFly, EJBCA home or database) or a failed check stop it
#  before anything is changed.
#
#  PHASES (mode fresh)
#     1  Plan            validate config, print the plan, confirm
#     2  Bundle          verify SHA256SUMS of the offline bundle
#     3  Pre-flight      OS, empty target, HSM library present
#     4  Packages        local apt repository + OS_PACKAGES
#     5  Database        MariaDB: secure, create database and user
#     6  WildFly         unpack + configure (service, datasource, TLS listeners...)
#     7  EJBCA source    unpack the EJBCA source tag, check version
#     8  EJBCA conf      write conf/*.properties
#     9  Add-ons         addons/NAME/install-NAME.sh --mode pre-deploy  (with --addon)
#    10  Build + deploy  ant clean deployear, wait until EJBCA is up
#    11  Install         ant runinstall, ant deploy-keystore, reload
#    12  Add-ons         addons/NAME/install-NAME.sh --mode verify      (with --addon)
#    13  Finalise        ownership, service enabled, firewall, summary
#
#  MODE upgrade-from-7x differs in:
#     5  Database        import UPGRADE_DB_DUMP, then the 9.6.1 column change
#     8  EJBCA conf      no install.properties / SuperAdmin values;
#                        password.encryption.key only if PBE_ENCRYPTION_KEY
#                        is not "default"
#    10  Build + deploy  first start runs EJBCA's standard upgrade (7.x -> 9.x)
#    11  Upgrade         7.x TLS keystores, then post-upgrade (ant upgrade)
#    12  Add-ons         skipped: verify after the add-on's migrate-from-7x
# =============================================================================
set -euo pipefail

# ---------------------------------------------------------------------------
# Fixed values (WildFly's systemd unit hard-codes /opt/wildfly and user wildfly)
# ---------------------------------------------------------------------------
readonly FIXED_WILDFLY_HOME="/opt/wildfly"
readonly FIXED_WILDFLY_USER="wildfly"
readonly FIXED_WILDFLY_SERVICE="wildfly-standalone"

REQUIRED_KEYS=(
    JAVA_MAJOR WILDFLY_VERSION MARIADB_JDBC_VERSION EJBCA_PATCHES_TAG EJBCA_VERSION OS_PACKAGES
    BUNDLE_DIR EJBCA_HOME WILDFLY_HOME WILDFLY_USER WILDFLY_SERVICE
    EJBCA_HOSTNAME DN_SUFFIX HTTP_PORT HTTPS_PORT HEAP_SIZE_MB
    DB_ROOT_PASS DB_NAME DB_USER DB_PASS
    PBE_ENCRYPTION_KEY KS_PASS TS_PASS
    P11_LIB_NAME P11_LIB_FILE HSM_CFG_FILE
)
FRESH_KEYS=(SUPERADMIN_PASS)
UPGRADE_KEYS=(UPGRADE_DB_DUMP UPGRADE_TLS_KEYSTORE UPGRADE_TLS_TRUSTSTORE)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

info()    { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }
section() { echo -e "\n${BOLD}${CYAN}$*${NC}"; }

usage() { sed -n '/^#  USAGE/,/^#  The script/p' "$0" | sed 's/^#  \{0,1\}//' | head -n -1; }

load_config() {
    local file="$1"
    [[ -f "$file" ]] || error "Config file not found: ${file}"
    local owner perms
    owner=$(stat -c '%U' "$file"); perms=$(stat -c '%a' "$file")
    [[ "$owner" == "root" ]] || error "Config ${file} must be owned by root (is: ${owner})."
    [[ "${perms: -2}" == "00" ]] || error "Config ${file} must not be accessible by group/others (chmod 600; is: ${perms})."
    # shellcheck disable=SC1090
    source "$file"
    local missing=() keys=("${REQUIRED_KEYS[@]}")
    if [[ "$MODE" == "fresh" ]]; then keys+=("${FRESH_KEYS[@]}"); else keys+=("${UPGRADE_KEYS[@]}"); fi
    for k in "${keys[@]}"; do
        [[ -n "${!k:-}" ]] || missing+=("$k")
    done
    [[ ${#missing[@]} -eq 0 ]] || error "Config ${file}: missing or empty values: ${missing[*]}"
    [[ "$WILDFLY_HOME"    == "$FIXED_WILDFLY_HOME"    ]] || error "WILDFLY_HOME must be ${FIXED_WILDFLY_HOME} (fixed by WildFly's systemd unit)."
    [[ "$WILDFLY_USER"    == "$FIXED_WILDFLY_USER"    ]] || error "WILDFLY_USER must be ${FIXED_WILDFLY_USER} (fixed by WildFly's systemd unit)."
    [[ "$WILDFLY_SERVICE" == "$FIXED_WILDFLY_SERVICE" ]] || error "WILDFLY_SERVICE must be ${FIXED_WILDFLY_SERVICE}."
}

wait_for_wildfly() {
    local max=120 i=0
    info "Waiting for WildFly to reach running state (up to ${max}s)..."
    until "${WILDFLY_HOME}/bin/jboss-cli.sh" --connect \
            --command=':read-attribute(name=server-state)' 2>/dev/null \
            | grep -q '"running"'; do
        sleep 3; i=$((i+3))
        [[ $i -ge $max ]] && \
            error "WildFly did not start within ${max}s. Check: ${WILDFLY_HOME}/standalone/log/server.log"
    done
    info "WildFly is running."
}

# jboss-cli with one retry when a command lands in a reload window.
cli() {
    local output exit_code=0
    output=$("${WILDFLY_HOME}/bin/jboss-cli.sh" --connect "$@" 2>&1) || exit_code=$?
    if [[ $exit_code -ne 0 ]] && echo "${output}" | grep -q "CancellationException"; then
        warn "CLI command cancelled (WildFly mid-reload) - retrying in 8s..."
        sleep 8
        "${WILDFLY_HOME}/bin/jboss-cli.sh" --connect "$@"
    else
        echo "${output}"
        return $exit_code
    fi
}

cli_reload() {
    sleep 3
    "${WILDFLY_HOME}/bin/jboss-cli.sh" --connect ':reload' 2>/dev/null || true
    sleep 6
    wait_for_wildfly
}

mysql_root() { mysql -u root -p"${DB_ROOT_PASS}" "$@"; }

is_upgrade() { [[ "$MODE" == "upgrade-from-7x" ]]; }

# Value of KEY in EJBCA's UPGRADE global configuration. EJBCA stores it as a
# serialized Java map (org.cesecore.util.Base64GetHashMap), read here with a
# small Perl reader of the Java serialization format (strings, references,
# objects, HashMap entries). Values may carry a "B64:" prefix.
UPGVAL_PL='use strict; use warnings;
my ($key, $hex) = @ARGV;
my $d = pack("H*", $hex // ""); my $p = 0; my @h; my @pairs;
sub rd  { my $n = shift; die "eof\n" if $p + $n > length $d; my $s = substr($d, $p, $n); $p += $n; $s }
sub u8  { ord rd(1) }  sub u16 { unpack "n", rd(2) }  sub u32 { unpack "N", rd(4) }
sub utf { rd(u16()) }
sub content {
    my $t = u8();
    if ($t == 0x70) { return undef }                                   # TC_NULL
    if ($t == 0x71) { return $h[u32() - 0x7E0000] }                    # TC_REFERENCE
    if ($t == 0x74) { my $s = utf(); push @h, $s; return $s }          # TC_STRING
    if ($t == 0x7C) { rd(4); my $s = rd(u32()); push @h, $s; return $s } # TC_LONGSTRING
    if ($t == 0x77) { rd(u8());  return { block => 1 } }               # TC_BLOCKDATA
    if ($t == 0x7A) { rd(u32()); return { block => 1 } }               # TC_BLOCKDATALONG
    if ($t == 0x72) { return classdesc() }                             # TC_CLASSDESC
    if ($t == 0x73) { return object() }                                # TC_OBJECT
    if ($t == 0x7E) { my $c = content(); my $i = @h; push @h, undef; my $v = content(); $h[$i] = $v; return $v } # TC_ENUM
    if ($t == 0x75) { my $c = content(); push @h, undef; my $n = u32(); fieldval(substr($c->{name}, 1, 1)) for 1..$n; return {} } # TC_ARRAY
    die sprintf("unsupported tag 0x%02x at %d\n", $t, $p - 1);
}
sub classdesc {
    my %c = (name => utf()); rd(8); push @h, \%c;
    $c{flags} = u8(); my $n = u16(); $c{fields} = [];
    for (1..$n) { my $tc = chr u8(); my $fn = utf(); content() if $tc eq "L" || $tc eq "["; push @{$c{fields}}, $tc }
    1 while defined(annot());                                          # classAnnotation
    $c{super} = content();
    return \%c;
}
sub annot { return undef if substr($d, $p, 1) eq "\x78" && ++$p; return [content()] }
my %size = (B=>1, C=>2, D=>8, F=>4, I=>4, J=>8, S=>2, Z=>1);
sub fieldval { my $tc = shift; return content() if $tc eq "L" || $tc eq "["; rd($size{$tc}); undef }
sub object {
    my $c = content(); push @h, { obj => 1 };
    my @chain; for (my $x = $c; ref $x eq "HASH" && $x->{name}; $x = $x->{super}) { unshift @chain, $x }
    for my $cd (@chain) {
        fieldval($_) for @{$cd->{fields}};
        next unless $cd->{flags} & 0x01;                               # SC_WRITE_METHOD
        my @items; while (defined(my $a = annot())) { push @items, $a->[0] }
        if ($cd->{name} eq "java.util.HashMap") {                      # keys/values after the block data
            my @kv = grep { !(ref $_ eq "HASH" && $_->{block}) } @items;
            push @pairs, [splice(@kv, 0, 2)] while @kv >= 2;
        }
    }
    return $h[-1];
}
eval { die "no stream\n" unless rd(2) eq "\xAC\xED"; rd(2); content(); 1 } or exit 1;
for (@pairs) { if (defined $_->[0] && !ref $_->[0] && $_->[0] eq $key && defined $_->[1] && !ref $_->[1]) { print "$_->[1]\n"; exit 0 } }
exit 1'
upgrade_value() {
    local key="$1" hex val
    hex="$(mysql_root -N -B "${DB_NAME}" -e "SELECT HEX(data) FROM GlobalConfigurationData WHERE configurationId='UPGRADE'" 2>/dev/null)" || return 1
    [[ -n "$hex" ]] || return 1
    val="$(perl -e "$UPGVAL_PL" "$key" "$hex")" || return 1
    [[ "$val" == B64:* ]] && val="$(printf '%s' "${val#B64:}" | base64 -d 2>/dev/null || true)"
    printf '%s\n' "$val"
}

# ---------------------------------------------------------------------------
# Arguments
# ---------------------------------------------------------------------------
CONFIG=""; MODE=""; ASSUME_YES=false; ADDONS=()

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --config) CONFIG="${2:?--config needs a value}"; shift 2 ;;
            --mode)   MODE="${2:?--mode needs a value}";     shift 2 ;;
            --addon)  ADDONS+=("${2:?--addon needs a value}"); shift 2 ;;
            --yes)    ASSUME_YES=true; shift ;;
            --help|-h) usage; exit 0 ;;
            *) error "Unknown option: $1 (see --help)" ;;
        esac
    done
    [[ -n "$CONFIG" ]] || error "--config is required (see --help)."
    [[ -n "$MODE"   ]] || error "--mode is required (see --help)."
    case "$MODE" in
        fresh|upgrade-from-7x) ;;
        *) error "Unknown mode: ${MODE} (fresh | upgrade-from-7x)" ;;
    esac
    CONFIG="$(readlink -f "$CONFIG")"
    local a
    for a in "${ADDONS[@]}"; do
        [[ "$a" =~ ^[a-z0-9]+$ ]] || error "--addon takes an add-on name (e.g. ed25519), not a path: ${a}"
    done
}

# Installer of add-on NAME inside the unpacked EJBCA source.
addon_installer() { echo "${EJBCA_HOME}/addons/${1}/install-${1}.sh"; }

# ---------------------------------------------------------------------------
# PHASE 1 - PLAN
# ---------------------------------------------------------------------------
phase1_plan() {
    section "=== Phase 1: Plan ==="
    load_config "$CONFIG"

    # keytool (used by ant runinstall / deploy-keystore) refuses passwords under 6 characters.
    local k
    for k in KS_PASS TS_PASS; do
        local v="${!k}"
        [[ ${#v} -ge 6 ]] || error "${k} must be at least 6 characters (keytool requirement)."
    done

    # PBE_ENCRYPTION_KEY="default" means: leave password.encryption.key out of
    # cesecore.properties (EJBCA's built-in key). Only valid for an upgrade whose
    # 7.x instance never set it; a new installation must use its own key.
    if is_upgrade; then
        local f
        for f in "${UPGRADE_DB_DUMP}" "${UPGRADE_TLS_KEYSTORE}" "${UPGRADE_TLS_TRUSTSTORE}"; do
            [[ -r "$f" ]] || error "Upgrade file not found or not readable: ${f}"
        done
    else
        [[ "${PBE_ENCRYPTION_KEY}" != "default" ]] \
            || error "PBE_ENCRYPTION_KEY=\"default\" is only for upgrade-from-7x. A new installation needs its own key."
    fi

    # Tag scheme <generation>.<ejbca-code>.<patch>: 2.963.0 belongs to EJBCA 9.6.3.
    local tag_code="${EJBCA_PATCHES_TAG#v}"; tag_code="${tag_code#*.}"; tag_code="${tag_code%%.*}"
    [[ "$tag_code" == "${EJBCA_VERSION//./}" ]] \
        || error "EJBCA_PATCHES_TAG ${EJBCA_PATCHES_TAG} is not a tag for EJBCA ${EJBCA_VERSION} (expected ?.${EJBCA_VERSION//./}.x)."

    WILDFLY_INSTALL_DIR="/opt/wildfly-${WILDFLY_VERSION}"
    WILDFLY_ZIP="${BUNDLE_DIR}/wildfly/wildfly-${WILDFLY_VERSION}.zip"
    MARIADB_JDBC_JAR="mariadb-java-client-${MARIADB_JDBC_VERSION}.jar"
    MARIADB_JDBC_FILE="${BUNDLE_DIR}/wildfly/${MARIADB_JDBC_JAR}"
    EJBCA_ARCHIVE="${BUNDLE_DIR}/ejbca/ejbca-${EJBCA_PATCHES_TAG}.tar.gz"
    WILDFLY_MAJOR="${WILDFLY_VERSION%%.*}"

    echo ""
    echo -e "${BOLD}======================================================${NC}"
    echo -e "${BOLD}  Installation plan  (mode: ${MODE})${NC}"
    echo -e "${BOLD}======================================================${NC}"
    printf "  %-22s %s\n" "Config:"        "${CONFIG}"
    printf "  %-22s %s\n" "Bundle:"        "${BUNDLE_DIR}"
    printf "  %-22s %s\n" "OS packages:"   "${OS_PACKAGES}"
    printf "  %-22s %s\n" "WildFly:"       "${WILDFLY_VERSION} -> ${WILDFLY_INSTALL_DIR} (link ${WILDFLY_HOME})"
    printf "  %-22s %s\n" "MariaDB JDBC:"  "${MARIADB_JDBC_VERSION}"
    printf "  %-22s %s\n" "EJBCA source:"  "tag ${EJBCA_PATCHES_TAG} (EJBCA ${EJBCA_VERSION}) -> ${EJBCA_HOME}"
    printf "  %-22s %s\n" "Database:"      "${DB_NAME} (user ${DB_USER}) - must not exist yet"
    if is_upgrade; then
        printf "  %-22s %s\n" "7.x database dump:" "${UPGRADE_DB_DUMP} -> imported into ${DB_NAME}"
        printf "  %-22s %s\n" "7.x TLS keystores:" "${UPGRADE_TLS_KEYSTORE}, ${UPGRADE_TLS_TRUSTSTORE}"
        if [[ "${PBE_ENCRYPTION_KEY}" == "default" ]]; then
            printf "  %-22s %s\n" "Encryption key:" "EJBCA default (password.encryption.key not set, as on 7.x)"
        else
            printf "  %-22s %s\n" "Encryption key:" "PBE_ENCRYPTION_KEY (must be the 7.x instance's value)"
        fi
        printf "  %-22s %s\n" "Not created:"   "ManagementCA, SuperAdmin, TLS certificate (they come from 7.x)"
        printf "  %-22s %s\n" "First start:"   "EJBCA standard upgrade 7.x -> ${EJBCA_VERSION}, then post-upgrade"
    fi
    printf "  %-22s %s\n" "Hostname:"      "${EJBCA_HOSTNAME}"
    printf "  %-22s %s\n" "Ports:"         "HTTP ${HTTP_PORT} / HTTPS ${HTTPS_PORT}"
    printf "  %-22s %s\n" "HSM library:"   "${P11_LIB_FILE}"
    printf "  %-22s %s\n" "HSM config:"    "${HSM_CFG_FILE}  (CS_PKCS11_R3_CFG for WildFly)"
    if [[ ${#ADDONS[@]} -gt 0 ]]; then
        local a
        for a in "${ADDONS[@]}"; do
            printf "  %-22s %s\n" "Add-on:" "${a}  ($(addon_installer "$a"): pre-deploy before build, verify at the end)"
        done
    else
        printf "  %-22s %s\n" "Add-ons:" "(none)"
    fi
    echo -e "${BOLD}======================================================${NC}"
    if is_upgrade; then
        echo ""
        warn "The 7.x instance must be STOPPED for good before this runs: both use the same"
        warn "HSM keys, and two instances signing with them create duplicate serials/CRLs."
        warn "This host must reach the HSM (HSM_CFG_FILE). After post-upgrade, the imported"
        warn "database can only be used by EJBCA ${EJBCA_VERSION}; the 7.x database is not touched."
    fi
    echo ""
    if ! $ASSUME_YES; then
        read -r -p "Proceed with this plan? [y/N] " ans
        [[ "${ans,,}" == "y" || "${ans,,}" == "yes" ]] || { info "Aborted."; exit 0; }
    fi
}

# ---------------------------------------------------------------------------
# PHASE 2 - BUNDLE
# ---------------------------------------------------------------------------
phase2_bundle() {
    section "=== Phase 2: Verifying offline bundle ==="
    [[ -f "${BUNDLE_DIR}/SHA256SUMS" ]] || error "No SHA256SUMS in ${BUNDLE_DIR}."
    ( cd "${BUNDLE_DIR}" && sha256sum --quiet -c SHA256SUMS ) \
        || error "Bundle checksum verification failed (see lines above)."
    local f
    for f in "${BUNDLE_DIR}/os/Packages.gz" "${WILDFLY_ZIP}" "${MARIADB_JDBC_FILE}" "${EJBCA_ARCHIVE}"; do
        [[ -f "$f" ]] || error "Missing from bundle: ${f}"
    done
    info "Bundle verified."
}

# ---------------------------------------------------------------------------
# PHASE 3 - PRE-FLIGHT
# ---------------------------------------------------------------------------
phase3_preflight() {
    section "=== Phase 3: Pre-flight checks ==="
    # shellcheck disable=SC1091
    . /etc/os-release
    if [[ "${ID:-}" != "ubuntu" || "${VERSION_ID:-}" != "22.04" ]]; then
        warn "Tested on Ubuntu 22.04; this host is ${PRETTY_NAME:-unknown}."
    fi
    [[ ! -e "${WILDFLY_INSTALL_DIR}" ]] || error "${WILDFLY_INSTALL_DIR} already exists - mode fresh needs a clean host (see workbook: resetting a test host)."
    [[ ! -e "${WILDFLY_HOME}" ]]        || error "${WILDFLY_HOME} already exists - mode fresh needs a clean host."
    [[ ! -e "${EJBCA_HOME}" ]]          || error "${EJBCA_HOME} already exists - mode fresh needs a clean host."
    [[ -f "${P11_LIB_FILE}" ]]          || error "HSM library not found: ${P11_LIB_FILE} (install the Utimaco PKCS#11 library first)."
    [[ -f "${HSM_CFG_FILE}" ]]          || error "HSM config not found: ${HSM_CFG_FILE} (HSM_CFG_FILE)."
    info "Pre-flight checks passed."
}

# ---------------------------------------------------------------------------
# PHASE 4 - PACKAGES (local apt repository from the bundle)
# ---------------------------------------------------------------------------
phase4_packages() {
    section "=== Phase 4: Installing OS packages from the bundle ==="
    local list="/etc/apt/sources.list.d/ejbca-bundle.list"
    echo "deb [trusted=yes] file:${BUNDLE_DIR}/os ./" > "${list}"
    # Only the bundle repository is used, so stale online package lists can't interfere.
    local apt_opts=(-o "Dir::Etc::sourcelist=${list}" -o "Dir::Etc::sourceparts=-" -o "APT::Get::List-Cleanup=0")
    apt-get "${apt_opts[@]}" update -qq
    # shellcheck disable=SC2086
    DEBIAN_FRONTEND=noninteractive apt-get "${apt_opts[@]}" install -y -qq ${OS_PACKAGES}

    local jpath="/usr/lib/jvm/java-${JAVA_MAJOR}-openjdk-amd64/bin/java"
    [[ -x "$jpath" ]] || error "Java ${JAVA_MAJOR} binary not found at ${jpath}."
    update-alternatives --set java "$jpath" >/dev/null
    JAVA_HOME=$(dirname "$(dirname "$(readlink -f "$jpath")")")
    export JAVA_HOME
    info "Java: $(java -version 2>&1 | head -1) at ${JAVA_HOME}."
    info "Ant:  $(ant -version 2>&1 | head -1)."

    if is_upgrade; then
        keytool -list -keystore "${UPGRADE_TLS_KEYSTORE}" -storepass "${KS_PASS}" >/dev/null 2>&1 \
            || error "Cannot open ${UPGRADE_TLS_KEYSTORE} with KS_PASS (it must be the 7.x keystore password)."
        keytool -list -keystore "${UPGRADE_TLS_TRUSTSTORE}" -storepass "${TS_PASS}" >/dev/null 2>&1 \
            || error "Cannot open ${UPGRADE_TLS_TRUSTSTORE} with TS_PASS (it must be the 7.x truststore password)."
        info "7.x TLS keystore: $(keytool -list -v -keystore "${UPGRADE_TLS_KEYSTORE}" -storepass "${KS_PASS}" 2>/dev/null | grep -m1 '^Owner:' || echo '?')"
    fi
}

# ---------------------------------------------------------------------------
# PHASE 5 - DATABASE
# ---------------------------------------------------------------------------
phase5_database() {
    section "=== Phase 5: Configuring MariaDB ==="
    systemctl enable --now mariadb

    # Secure root on a freshly installed MariaDB (fails harmlessly if already set).
    mysql -u root 2>/dev/null <<SQL || true
ALTER USER 'root'@'localhost' IDENTIFIED BY '${DB_ROOT_PASS}';
DELETE FROM mysql.user WHERE User='';
DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost','127.0.0.1','::1');
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';
FLUSH PRIVILEGES;
SQL
    mysql_root -e "SELECT 1;" >/dev/null 2>&1 \
        || error "Cannot log in to MariaDB as root with DB_ROOT_PASS."

    local tables
    tables=$(mysql_root -sN -e "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='${DB_NAME}';")
    [[ "${tables}" -eq 0 ]] || error "Database '${DB_NAME}' already has ${tables} tables - mode fresh needs an empty database."

    mysql_root <<SQL
CREATE DATABASE IF NOT EXISTS ${DB_NAME} CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS '${DB_USER}'@'localhost' IDENTIFIED BY '${DB_PASS}';
GRANT ALL PRIVILEGES ON ${DB_NAME}.* TO '${DB_USER}'@'localhost';
FLUSH PRIVILEGES;
SQL
    info "Database '${DB_NAME}' and user '${DB_USER}' ready."

    if is_upgrade; then
        local cat_cmd=(cat)
        [[ "${UPGRADE_DB_DUMP}" == *.gz ]] && cat_cmd=(zcat)
        local dbstmts
        dbstmts=$("${cat_cmd[@]}" "${UPGRADE_DB_DUMP}" | grep -ciE '^(CREATE DATABASE|USE )' || true)
        if [[ "${dbstmts:-0}" -gt 0 ]]; then
            error "${UPGRADE_DB_DUMP} contains CREATE DATABASE/USE statements. Dump the 7.x database without --databases: mysqldump --single-transaction --routines --triggers <db> | gzip > dump.sql.gz"
        fi
        info "Importing ${UPGRADE_DB_DUMP} into ${DB_NAME}..."
        "${cat_cmd[@]}" "${UPGRADE_DB_DUMP}" | mysql_root "${DB_NAME}" || error "Import of ${UPGRADE_DB_DUMP} failed."
        local cas from
        cas=$(mysql_root -sN "${DB_NAME}" -e "SELECT COUNT(*) FROM CAData;" 2>/dev/null || echo 0)
        [[ "$cas" -ge 1 ]] || error "The imported database has no CAData rows - not an EJBCA database?"
        from="$(upgrade_value upgradedToVersion || true)"
        [[ "$from" == 7.* ]] || error "The imported database is EJBCA '${from:-unknown}', not 7.x."
        # EJBCA 9.6.1 enlarged subjectAltName; Hibernate adds new columns itself but never resizes them.
        mysql_root "${DB_NAME}" <<SQL || error "subjectAltName column update failed."
ALTER TABLE IF EXISTS UserData MODIFY subjectAltName VARCHAR(8000) BINARY;
ALTER TABLE IF EXISTS CertificateData MODIFY subjectAltName VARCHAR(8000) BINARY;
ALTER TABLE IF EXISTS NoConflictCertificateData MODIFY subjectAltName VARCHAR(8000) BINARY;
SQL
        info "7.x database imported (EJBCA ${from}, ${cas} CA(s)); 9.6.1 column change applied."
    fi
}

# ---------------------------------------------------------------------------
# PHASE 6 - WILDFLY
# ---------------------------------------------------------------------------
phase6_wildfly() {
    section "=== Phase 6: Installing and configuring WildFly ${WILDFLY_VERSION} ==="
    unzip -q "${WILDFLY_ZIP}" -d /opt/
    ln -snf "${WILDFLY_INSTALL_DIR}" "${WILDFLY_HOME}"
    info "WildFly unpacked -> ${WILDFLY_INSTALL_DIR} (link ${WILDFLY_HOME})."

    # Remove RESTEasy-Crypto to avoid Bouncy Castle version conflicts.
    local module_xml="${WILDFLY_HOME}/modules/system/layers/base/org/jboss/as/jaxrs/main/module.xml"
    [[ -f "$module_xml" ]] || error "Expected ${module_xml} not found - unsupported WildFly layout."
    sed -i '/.*org.jboss.resteasy.resteasy-crypto.*/d' "$module_xml"
    rm -rf "${WILDFLY_HOME}/modules/system/layers/base/org/jboss/resteasy/resteasy-crypto/"
    info "RESTEasy-Crypto removed."

    # ---- standalone.conf (POSIX sh: sourced by standalone.sh) ----
    local tx_node_id
    tx_node_id=$(od -A n -t d -N 1 /dev/urandom | tr -d ' ')
    cat > "${WILDFLY_HOME}/bin/standalone.conf" <<EOF
if [ "x\$JBOSS_MODULES_SYSTEM_PKGS" = "x" ]; then
     JBOSS_MODULES_SYSTEM_PKGS="org.jboss.byteman"
fi

# Appended unconditionally: WildFly's systemd launcher already puts options
# (e.g. -Djdk.serialFilter) into JAVA_OPTS before this file is read, so an
# "only if empty" block would be skipped and the JVM would run on default heap.
JAVA_OPTS="\$JAVA_OPTS -Xms${HEAP_SIZE_MB}m -Xmx${HEAP_SIZE_MB}m"
JAVA_OPTS="\$JAVA_OPTS -Dhttps.protocols=TLSv1.2,TLSv1.3"
JAVA_OPTS="\$JAVA_OPTS -Djdk.tls.client.protocols=TLSv1.2,TLSv1.3"
JAVA_OPTS="\$JAVA_OPTS -Djava.net.preferIPv4Stack=true"
JAVA_OPTS="\$JAVA_OPTS -Djboss.modules.system.pkgs=\$JBOSS_MODULES_SYSTEM_PKGS"
JAVA_OPTS="\$JAVA_OPTS -Djava.awt.headless=true"
JAVA_OPTS="\$JAVA_OPTS -Djboss.tx.node.id=${tx_node_id}"
JAVA_OPTS="\$JAVA_OPTS -XX:+HeapDumpOnOutOfMemoryError"
JAVA_OPTS="\$JAVA_OPTS -Djdk.tls.ephemeralDHKeySize=2048"
# The first EJBCA deployment (and a 7.x database upgrade) can take minutes;
# WildFly rolls the deployment back after 300 s by default.
JAVA_OPTS="\$JAVA_OPTS -Djboss.as.management.blocking.timeout=900"

# PKCS#11 (SunPKCS11 internals) access for EJBCA and the HSM add-ons on Java 17+.
JAVA_OPTS="\$JAVA_OPTS --add-exports=jdk.crypto.cryptoki/sun.security.pkcs11.wrapper=ALL-UNNAMED"
EOF
    info "standalone.conf written (heap=${HEAP_SIZE_MB}MB, tx-node=${tx_node_id})."

    # ---- systemd service ----
    mkdir -p /etc/sysconfig
    cp "${WILDFLY_HOME}/bin/systemd/wildfly-standalone.service" /etc/systemd/system/
    cat > /etc/sysconfig/wildfly-standalone.conf <<EOF
# WildFly standalone service environment - generated by install-ejbca.sh
WILDFLY_HOME="${WILDFLY_INSTALL_DIR}"
JAVA_HOME="${JAVA_HOME}"
# Must be set (even to false): launch.sh tests it and /bin/sh is dash on Ubuntu.
WILDFLY_SYSTEMD_DEBUG="false"
# Utimaco PKCS#11 library configuration (otherwise /etc/utimaco/cs_pkcs11_R3.cfg).
CS_PKCS11_R3_CFG="${HSM_CFG_FILE}"
EOF
    # Start WildFly only after MariaDB, so EJBCA's datasource is available at boot.
    mkdir -p "/etc/systemd/system/${WILDFLY_SERVICE}.service.d"
    printf '[Unit]\nAfter=mariadb.service\nWants=mariadb.service\n' \
        > "/etc/systemd/system/${WILDFLY_SERVICE}.service.d/10-mariadb.conf"
    # launch.sh uses '==' inside [ ] (a bashism); Ubuntu's /bin/sh (dash) needs '='.
    local launch_sh="${WILDFLY_HOME}/bin/systemd/launch.sh"
    [[ -f "$launch_sh" ]] || error "${launch_sh} not found - unsupported WildFly layout."
    sed -i 's/==/=/g' "$launch_sh"

    systemctl daemon-reload
    id "${WILDFLY_USER}" &>/dev/null || useradd -r -s /bin/false "${WILDFLY_USER}"
    chown -R "${WILDFLY_USER}:${WILDFLY_USER}" "${WILDFLY_INSTALL_DIR}/"

    # The HSM library runs inside WildFly, as the wildfly user.
    sudo -u "${WILDFLY_USER}" test -r "${P11_LIB_FILE}" \
        || error "${P11_LIB_FILE} is not readable by ${WILDFLY_USER}."
    sudo -u "${WILDFLY_USER}" test -r "${HSM_CFG_FILE}" \
        || error "${HSM_CFG_FILE} is not readable by ${WILDFLY_USER}."
    local hsm_logpath
    hsm_logpath=$(sed -n 's/^[[:space:]]*Logpath[[:space:]]*=[[:space:]]*//Ip' "${HSM_CFG_FILE}" | head -1 | tr -d ' \r"')
    if [[ -n "$hsm_logpath" ]] && ! sudo -u "${WILDFLY_USER}" test -w "$hsm_logpath"; then
        warn "HSM Logpath ${hsm_logpath} is not writable by ${WILDFLY_USER}; the HSM library may fail to initialise."
    fi

    systemctl start "${WILDFLY_SERVICE}"
    wait_for_wildfly

    # ---- Elytron credential store ----
    local pass_script="/usr/bin/wildfly_pass"
    printf '#!/bin/sh\necho '"'"'%s'"'"'\n' "$(openssl rand -base64 24)" > "$pass_script"
    chown "${WILDFLY_USER}:${WILDFLY_USER}" "$pass_script"
    chmod 700 "$pass_script"
    mkdir -p "${WILDFLY_HOME}/standalone/configuration/keystore"
    chown "${WILDFLY_USER}:${WILDFLY_USER}" "${WILDFLY_HOME}/standalone/configuration/keystore"
    cli "/subsystem=elytron/credential-store=defaultCS:add(\
path=keystore/credentials,\
relative-to=jboss.server.config.dir,\
credential-reference={clear-text=\"{EXT}${pass_script}\", type=\"COMMAND\"},\
create=true)"

    # ---- MariaDB JDBC driver (hot-deploy, from the bundle) ----
    cp "${MARIADB_JDBC_FILE}" "${WILDFLY_HOME}/standalone/deployments/"
    chown "${WILDFLY_USER}:${WILDFLY_USER}" "${WILDFLY_HOME}/standalone/deployments/${MARIADB_JDBC_JAR}"
    info "Waiting for JDBC driver hot-deployment (8s)..."
    sleep 8

    # ---- Datasource ----
    cli "/subsystem=elytron/credential-store=defaultCS:add-alias(alias=dbPassword, secret-value=\"${DB_PASS}\")"
    cli "data-source add \
--name=ejbcads \
--connection-url=\"jdbc:mariadb://127.0.0.1:3306/${DB_NAME}\" \
--jndi-name=\"java:/EjbcaDS\" \
--use-ccm=true \
--driver-name=\"${MARIADB_JDBC_JAR}\" \
--driver-class=\"org.mariadb.jdbc.Driver\" \
--user-name=\"${DB_USER}\" \
--credential-reference={store=defaultCS, alias=dbPassword} \
--validate-on-match=true \
--background-validation=false \
--prepared-statements-cache-size=50 \
--share-prepared-statements=true \
--min-pool-size=5 \
--max-pool-size=150 \
--pool-prefill=true \
--transaction-isolation=TRANSACTION_READ_COMMITTED \
--check-valid-connection-sql=\"select 1;\""
    cli_reload

    # ---- Remoting on port 4447 (required by the EJBCA CLI) ----
    cli '/subsystem=remoting/http-connector=http-remoting-connector:write-attribute(name=connector-ref,value=remoting)'
    cli '/socket-binding-group=standard-sockets/socket-binding=remoting:add(port=4447,interface=management)'
    cli '/subsystem=undertow/server=default-server/http-listener=remoting:add(socket-binding=remoting,enable-http2=true)'
    cli_reload

    # ---- WildFly 38+: remove file passivation store of the web session cache (standalone) ----
    if [[ "${WILDFLY_MAJOR}" -ge 38 ]]; then
        cli '/subsystem=infinispan/cache-container=web/local-cache=passivation/store=file:remove' 2>/dev/null || true
        cli_reload
    fi

    # ---- Logging ----
    cli '/subsystem=logging/logger=org.ejbca:add(level=INFO)'
    cli '/subsystem=logging/logger=org.cesecore:add(level=INFO)'
    cli '/subsystem=logging/logger=com.keyfactor:add(level=INFO)'
    cli '/subsystem=undertow/server=default-server/host=default-host/setting=access-log:add(pattern="%h %t \"%r\" %s \"%{i,User-Agent}\"",relative-to=jboss.server.log.dir,directory=access-logs)'
    cli '/subsystem=logging/logger=io.undertow.accesslog:add(level=INFO)'

    # ---- Replace default HTTP/HTTPS listeners ----
    cli '/subsystem=undertow/server=default-server/http-listener=default:remove()'
    cli '/socket-binding-group=standard-sockets/socket-binding=http:remove()'
    cli '/subsystem=undertow/server=default-server/https-listener=https:remove()'
    cli '/socket-binding-group=standard-sockets/socket-binding=https:remove()'
    cli_reload

    # ---- 2-port separation: HTTP / HTTPS (optional client certificate) ----
    cli '/interface=http:add(inet-address="0.0.0.0")'
    cli '/interface=https:add(inet-address="0.0.0.0")'
    cli "/socket-binding-group=standard-sockets/socket-binding=http:add(port=\"${HTTP_PORT}\",interface=\"http\")"
    cli "/socket-binding-group=standard-sockets/socket-binding=https:add(port=\"${HTTPS_PORT}\",interface=\"https\")"
    cli "/subsystem=elytron/credential-store=defaultCS:add-alias(alias=httpsKeystorePassword, secret-value=\"${KS_PASS}\")"
    cli "/subsystem=elytron/credential-store=defaultCS:add-alias(alias=httpsTruststorePassword, secret-value=\"${TS_PASS}\")"
    cli '/subsystem=elytron/key-store=httpsKS:add(path="keystore/keystore.p12",relative-to=jboss.server.config.dir,credential-reference={store=defaultCS, alias=httpsKeystorePassword},type=PKCS12)'
    cli '/subsystem=elytron/key-store=httpsTS:add(path="keystore/truststore.p12",relative-to=jboss.server.config.dir,credential-reference={store=defaultCS, alias=httpsTruststorePassword},type=PKCS12)'
    cli '/subsystem=elytron/key-manager=httpsKM:add(key-store=httpsKS,algorithm="SunX509",credential-reference={store=defaultCS, alias=httpsKeystorePassword})'
    cli '/subsystem=elytron/trust-manager=httpsTM:add(key-store=httpsTS)'

    local cipher_filter="TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,\
TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,\
TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,\
TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,\
TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,\
TLS_RSA_WITH_AES_256_CBC_SHA256,\
TLS_RSA_WITH_AES_256_CBC_SHA,\
TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,\
TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,\
TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,\
TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,\
TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,\
TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"
    local tls13_suites="TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256"
    cli "/subsystem=elytron/server-ssl-context=https:add(\
key-manager=httpsKM,\
protocols=[\"TLSv1.3\",\"TLSv1.2\"],\
use-cipher-suites-order=false,\
cipher-suite-filter=\"${cipher_filter}\",\
cipher-suite-names=\"${tls13_suites}\",\
trust-manager=httpsTM,\
want-client-auth=true,\
authentication-optional=true)"
    cli '/subsystem=undertow/server=default-server/http-listener=http:add(socket-binding="http", redirect-socket="https")'
    cli '/subsystem=undertow/server=default-server/https-listener=https:add(socket-binding="https", ssl-context="https", max-parameters=2048)'
    cli_reload

    # ---- HTTP protocol settings (OCSP GET, WSDL, encoded characters) ----
    cli '/system-property=org.apache.catalina.connector.URI_ENCODING:add(value="UTF-8")'
    cli '/system-property=org.apache.catalina.connector.USE_BODY_ENCODING_FOR_QUERY_STRING:add(value=true)'
    cli '/system-property=org.apache.tomcat.util.buf.UDecoder.ALLOW_ENCODED_SLASH:add(value=true)'
    cli '/system-property=org.apache.tomcat.util.http.Parameters.MAX_COUNT:add(value=2048)'
    cli '/system-property=org.apache.catalina.connector.CoyoteAdapter.ALLOW_BACKSLASH:add(value=true)'
    cli '/subsystem=webservices:write-attribute(name=wsdl-host, value=jbossws.undefined.host)'
    cli '/subsystem=webservices:write-attribute(name=modify-wsdl-address, value=true)'
    cli_reload

    # ---- Remove defaults EJBCA does not use (absent in some WildFly layouts) ----
    cli '/subsystem=ee/service=default-bindings:remove()' 2>/dev/null || true
    cli 'data-source remove --name=ExampleDS'             2>/dev/null || true
    cli '/socket-binding-group=standard-sockets/socket-binding=ajp:remove()' 2>/dev/null || true
    cli_reload

    cli ':take-snapshot(name="Pre-EJBCA WildFly configuration")'
    info "WildFly configuration complete."
}

# ---------------------------------------------------------------------------
# PHASE 7 - EJBCA SOURCE
# ---------------------------------------------------------------------------
phase7_ejbca_source() {
    section "=== Phase 7: Unpacking EJBCA source (${EJBCA_PATCHES_TAG}) ==="
    mkdir -p "${EJBCA_HOME}"
    # GitHub tag archives have one top-level directory; strip it.
    tar -xzf "${EJBCA_ARCHIVE}" --strip-components=1 -C "${EJBCA_HOME}"
    chmod -R u+rwX,go+rX "${EJBCA_HOME}"

    local found
    found=$(grep '^app.version.number=' "${EJBCA_HOME}/src/internal.properties" | cut -d= -f2 | tr -d ' \r')
    [[ "$found" == "$EJBCA_VERSION" ]] \
        || error "EJBCA source is version '${found}', config expects '${EJBCA_VERSION}'."
    info "EJBCA source ${found} unpacked -> ${EJBCA_HOME}."

    if grep -q 'ejbca.jboss-ds.xml' "${EJBCA_HOME}/build.xml"; then
        info "Add-on plugin hook present in build.xml."
    elif [[ ${#ADDONS[@]} -gt 0 ]]; then
        error "build.xml has no add-on plugin hook - this EJBCA source cannot build add-ons in."
    fi

    local a inst
    for a in "${ADDONS[@]}"; do
        inst="$(addon_installer "$a")"
        [[ -x "$inst" ]] || error "Add-on '${a}' is not in this EJBCA source (${inst} missing)."
        info "Add-on ${a} $(cat "${EJBCA_HOME}/addons/${a}/VERSION" 2>/dev/null || echo '(no VERSION file)') present."
    done
}

# ---------------------------------------------------------------------------
# PHASE 8 - EJBCA CONFIGURATION FILES
# ---------------------------------------------------------------------------
phase8_ejbca_conf() {
    section "=== Phase 8: Writing EJBCA configuration files ==="
    local conf="${EJBCA_HOME}/conf"

    cp "${conf}/database.properties.sample" "${conf}/database.properties"
    cat >> "${conf}/database.properties" <<EOF

# --- Added by install-ejbca.sh ---
database.name=mysql
datasource.jndi-name=EjbcaDS
EOF

    cp "${conf}/cesecore.properties.sample" "${conf}/cesecore.properties"
    cat >> "${conf}/cesecore.properties" <<EOF

# --- Added by install-ejbca.sh ---
EOF
    if [[ "${PBE_ENCRYPTION_KEY}" == "default" ]]; then
        echo "# password.encryption.key not set: EJBCA default, as on the 7.x instance." >> "${conf}/cesecore.properties"
    else
        cat >> "${conf}/cesecore.properties" <<EOF
# Must stay the same for the whole life of this instance (and its backups).
password.encryption.key=${PBE_ENCRYPTION_KEY}
EOF
    fi

    cp "${conf}/web.properties.sample" "${conf}/web.properties"
    cat >> "${conf}/web.properties" <<EOF

# --- Added by install-ejbca.sh ---
httpsserver.hostname=${EJBCA_HOSTNAME}
httpsserver.dn=CN=${EJBCA_HOSTNAME},${DN_SUFFIX}
httpsserver.an=dnsName=${EJBCA_HOSTNAME}
httpsserver.password=${KS_PASS}
httpsserver.tokentype=P12
java.trustpassword=${TS_PASS}
httpserver.pubhttp=${HTTP_PORT}
httpserver.privhttps=${HTTPS_PORT}
httpserver.pubhttps=${HTTPS_PORT}
cryptotoken.p11.lib.1.name=${P11_LIB_NAME}
cryptotoken.p11.lib.1.file=${P11_LIB_FILE}
EOF
    if ! is_upgrade; then
        cat >> "${conf}/web.properties" <<EOF
superadmin.password=${SUPERADMIN_PASS}
superadmin.cn=SuperAdmin
superadmin.dn=CN=SuperAdmin,${DN_SUFFIX}
superadmin.batch=true
EOF
    fi

    if ! is_upgrade; then
        cp "${conf}/install.properties.sample" "${conf}/install.properties"
        cat >> "${conf}/install.properties" <<EOF

# --- Added by install-ejbca.sh ---
ca.name=ManagementCA
ca.dn=CN=ManagementCA,${DN_SUFFIX}
ca.keytype=RSA
ca.keyspec=4096
ca.signaturealgorithm=SHA256WithRSA
ca.validity=3650
ca.tokentype=soft
ca.tokenpassword=null
ca.policy=null
ca.certificateprofile=ROOTCA
EOF
    fi

    cp "${conf}/ejbca.properties.sample" "${conf}/ejbca.properties"
    cat >> "${conf}/ejbca.properties" <<EOF

# --- Added by install-ejbca.sh ---
healthcheck.catokensigntest=true
EOF
    chmod 600 "${conf}"/*.properties
    info "EJBCA configuration files written."
}

# ---------------------------------------------------------------------------
# PHASE 9 / 12 - ADD-ON HOOKS
# ---------------------------------------------------------------------------
run_addons() {
    local mode="$1" a
    [[ ${#ADDONS[@]} -gt 0 ]] || { info "No add-ons requested."; return 0; }
    local inst
    for a in "${ADDONS[@]}"; do
        inst="$(addon_installer "$a")"
        info "Running: ${inst} --config ${CONFIG} --mode ${mode} --yes"
        "$inst" --config "${CONFIG}" --mode "${mode}" --yes \
            || error "Add-on ${a} failed in mode ${mode}."
    done
}

phase9_addons_predeploy() {
    section "=== Phase 9: Add-ons - pre-deploy ==="
    run_addons pre-deploy
}

# ---------------------------------------------------------------------------
# PHASE 10 - BUILD & DEPLOY
# ---------------------------------------------------------------------------
health_url() { echo "http://localhost:${HTTP_PORT}/ejbca/publicweb/healthcheck/ejbcahealth"; }

phase10_build_deploy() {
    section "=== Phase 10: Building and deploying EJBCA ==="
    export APPSRV_HOME="${WILDFLY_HOME}"
    export JAVA_HOME
    local stamp; stamp="$(mktemp)"
    ( cd "${EJBCA_HOME}" && ant -q clean deployear ) || error "ant clean deployear failed."

    if is_upgrade; then
        # The CA tokens are offline until the add-on migration, so the health
        # check is not ALLOK yet: wait for the deployment marker instead.
        local dep="${WILDFLY_HOME}/standalone/deployments" w=0
        info "Waiting for the deployment; EJBCA upgrades the 7.x database on this first start..."
        until [[ "${dep}/ejbca.ear.deployed" -nt "$stamp" ]]; do
            [[ -f "${dep}/ejbca.ear.failed" ]] && \
                error "EJBCA deployment failed:\n$(head -c 2000 "${dep}/ejbca.ear.failed")\nCheck: ${WILDFLY_HOME}/standalone/log/server.log"
            sleep 5; w=$((w+5))
            [[ $w -ge 960 ]] && error "ejbca.ear not deployed after ${w}s. Check: ${WILDFLY_HOME}/standalone/log/server.log"
            [[ $((w % 30)) -eq 0 ]] && info "  Still deploying... (${w}s)"
        done
        rm -f "$stamp"
        local to; to="$(upgrade_value upgradedToVersion || true)"
        [[ "$to" == "${EJBCA_VERSION}" ]] \
            || error "EJBCA deployed but the database reports version '${to}', not ${EJBCA_VERSION}. Check server.log for 'Starting upgrade'."
        info "EJBCA deployed; database upgraded to ${to}."
        return 0
    fi
    rm -f "$stamp"

    # ALLOK alone is not enough: during redeploy the old instance may still answer.
    # Wait for the endpoint to go down, then up, then for the EJBCA tables.
    local i=0
    sleep 5
    while curl -s --max-time 2 "$(health_url)" 2>/dev/null | grep -q "^ALLOK"; do
        sleep 3; i=$((i+3)); [[ $i -ge 60 ]] && break
    done
    local j=0 failed="${WILDFLY_HOME}/standalone/deployments/ejbca.ear.failed"
    until curl -s --max-time 3 "$(health_url)" 2>/dev/null | grep -q "^ALLOK"; do
        if [[ -f "$failed" ]]; then
            error "EJBCA deployment failed:\n$(head -c 2000 "$failed")\nCheck: ${WILDFLY_HOME}/standalone/log/server.log"
        fi
        sleep 5; j=$((j+5))
        [[ $j -ge 300 ]] && error "EJBCA health endpoint not ALLOK after ${j}s. Check: ${WILDFLY_HOME}/standalone/log/server.log"
        info "  Still initialising... (${j}s)"
    done
    local k=0
    until mysql -u"${DB_USER}" -p"${DB_PASS}" "${DB_NAME}" -e "SELECT 1 FROM CAData LIMIT 1;" &>/dev/null; do
        sleep 5; k=$((k+1)); [[ $k -ge 12 ]] && error "EJBCA tables not accessible after 60s."
    done
    sleep 5
    info "EJBCA is deployed and the database is ready."
}

# ---------------------------------------------------------------------------
# PHASE 11 - RUNINSTALL & KEYSTORES
# ---------------------------------------------------------------------------
phase11_runinstall() {
    section "=== Phase 11: EJBCA installation (ManagementCA, SuperAdmin, TLS) ==="
    export APPSRV_HOME="${WILDFLY_HOME}"
    export JAVA_HOME
    ( cd "${EJBCA_HOME}" && ant runinstall ) || error "ant runinstall failed."

    local cert_count
    cert_count=$(mysql -u"${DB_USER}" -p"${DB_PASS}" "${DB_NAME}" -sN \
        -e "SELECT COUNT(*) FROM CertificateData WHERE username='superadmin';" 2>/dev/null || echo 0)
    [[ "${cert_count}" -ge 1 ]] || error "ant runinstall finished but the SuperAdmin certificate is not in the database (EJBCA was not ready). Reset the host and run again."
    info "SuperAdmin certificate stored in the database."

    ( cd "${EJBCA_HOME}" && ant deploy-keystore ) || error "ant deploy-keystore failed."
    chown "${WILDFLY_USER}:${WILDFLY_USER}" "${WILDFLY_HOME}/standalone/configuration/keystore/"*.p12
    cli_reload
    info "TLS keystores deployed."
}

phase11_upgrade() {
    section "=== Phase 11: 7.x TLS keystores and post-upgrade ==="
    export APPSRV_HOME="${WILDFLY_HOME}"
    export JAVA_HOME
    local ksdir="${WILDFLY_HOME}/standalone/configuration/keystore"
    keytool -importkeystore -noprompt \
        -srckeystore "${UPGRADE_TLS_KEYSTORE}" -srcstorepass "${KS_PASS}" \
        -destkeystore "${ksdir}/keystore.p12" -deststoretype PKCS12 -deststorepass "${KS_PASS}" >/dev/null \
        || error "Could not copy ${UPGRADE_TLS_KEYSTORE} to ${ksdir}/keystore.p12."
    keytool -importkeystore -noprompt \
        -srckeystore "${UPGRADE_TLS_TRUSTSTORE}" -srcstorepass "${TS_PASS}" \
        -destkeystore "${ksdir}/truststore.p12" -deststoretype PKCS12 -deststorepass "${TS_PASS}" >/dev/null \
        || error "Could not copy ${UPGRADE_TLS_TRUSTSTORE} to ${ksdir}/truststore.p12."
    chown "${WILDFLY_USER}:${WILDFLY_USER}" "${ksdir}/"*.p12
    chmod 600 "${ksdir}/"*.p12
    cli_reload
    info "7.x TLS keystore and truststore in use."

    ( cd "${EJBCA_HOME}" && ant upgrade ) || error "ant upgrade (post-upgrade) failed. See ${WILDFLY_HOME}/standalone/log/server.log"
    local post; post="$(upgrade_value postUpgradedToVersion || true)"
    [[ "${post%%.*}" == "${EJBCA_VERSION%%.*}" ]] \
        || error "Post-upgrade did not complete (postUpgradedToVersion: '${post}'). Check Admin UI > System Upgrade."
    info "Post-upgrade complete (${post})."
}

phase12_addons_verify() {
    section "=== Phase 12: Add-ons - verify ==="
    if is_upgrade; then
        info "Skipped: the add-on check needs the migrated crypto tokens (see the next steps below)."
        return 0
    fi
    run_addons verify
}

# ---------------------------------------------------------------------------
# PHASE 13 - FINALISE
# ---------------------------------------------------------------------------
phase13_finalise() {
    section "=== Phase 13: Finalising ==="
    chown -R "${WILDFLY_USER}:${WILDFLY_USER}" "${WILDFLY_INSTALL_DIR}/"
    chown -R root:root "${EJBCA_HOME}/"
    systemctl enable "${WILDFLY_SERVICE}"

    if ufw status 2>/dev/null | grep -q "Status: active"; then
        ufw allow "${HTTP_PORT}/tcp"  comment "EJBCA HTTP"
        ufw allow "${HTTPS_PORT}/tcp" comment "EJBCA HTTPS"
        info "UFW rules added for ports ${HTTP_PORT} and ${HTTPS_PORT}."
    else
        warn "UFW is not active. Make sure ports ${HTTP_PORT} and ${HTTPS_PORT} are reachable."
    fi

    echo ""
    echo -e "${BOLD}${GREEN}======================================================${NC}"
    echo -e "${BOLD}${GREEN}  EJBCA ${EJBCA_VERSION} (${EJBCA_PATCHES_TAG}) - $(is_upgrade && echo "upgrade from 7.x complete" || echo "installation complete")${NC}"
    echo -e "${BOLD}${GREEN}======================================================${NC}"
    printf "  %-20s %s\n" "Admin UI:"       "https://${EJBCA_HOSTNAME}:${HTTPS_PORT}/ejbca/adminweb/"
    printf "  %-20s %s\n" "WildFly log:"    "${WILDFLY_HOME}/standalone/log/server.log"
    echo ""
    if is_upgrade; then
        echo "  Log in with the 7.x SuperAdmin certificate (its P12 from the 7.x instance)."
        echo "  Next, for each add-on (crypto tokens are offline until then):"
        local a
        for a in "${ADDONS[@]}"; do
            echo "    $(addon_installer "$a") --config ${CONFIG} --mode migrate-from-7x [--set-pins]"
            echo "    $(addon_installer "$a") --config ${CONFIG} --mode verify"
        done
    else
        printf "  %-20s %s\n" "SuperAdmin P12:" "${EJBCA_HOME}/p12/superadmin.p12"
        echo "  Next: copy superadmin.p12 to your workstation and import it in the browser"
        echo "        (password: SUPERADMIN_PASS from the config file)."
    fi
    echo -e "${BOLD}${GREEN}======================================================${NC}"
}

# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------
main() {
    [[ $EUID -eq 0 ]] || error "Run as root (sudo)."
    parse_args "$@"
    phase1_plan
    phase2_bundle
    phase3_preflight
    phase4_packages
    phase5_database
    phase6_wildfly
    phase7_ejbca_source
    phase8_ejbca_conf
    phase9_addons_predeploy
    phase10_build_deploy
    if is_upgrade; then phase11_upgrade; else phase11_runinstall; fi
    phase12_addons_verify
    phase13_finalise
}

main "$@"