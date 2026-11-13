#!/usr/bin/env bash
# shellcheck disable=SC2034  # ASSUME_YES is used by ask() in hsm-installer-lib.sh
# =============================================================================
# install-ed25519.sh  —  HSM Ed25519 add-on for EJBCA v2 (bare-metal, offline)
# =============================================================================
# Usage:
#   sudo ./install-ed25519.sh --config FILE --mode MODE [--set-pins] [--yes]
#
#   --config FILE   ejbca-install.conf (same file as install-ejbca.sh)  [required]
#   --mode MODE     pre-deploy       before "ant deployear": WildFly module,
#                                    standalone.xml (via jboss-cli), EJBCA
#                                    build plugin. WildFly must be running.
#                   verify           after deploy: checks EAR, WildFly config,
#                                    StartupBean registration, healthcheck
#                   migrate-from-7x  after "install-ejbca.sh --mode upgrade-from-7x"
#                                    (standard EJBCA upgrade + post-upgrade done):
#                                    converts every PKCS11CryptoToken to
#                                    HsmEd25519CryptoToken with P11_LIB_FILE.
#                                    Restarts WildFly.                  [required]
#   --set-pins      migrate-from-7x only: then ask for the PIN of each offline
#                   Ed25519 token (saved as its auto-activation PIN) and test
#                   every key. Interactive: cannot be combined with --yes.
#                   Without it, activate each converted token once in the
#                   Admin UI (Crypto Tokens > Activate).
#   --yes           do not ask for confirmation after the plan
#
# Shipped inside the EJBCA source at
# $EJBCA_HOME/addons/ed25519/, next to the add-on files it installs.
# It can also run from any other folder holding the release files; they are
# then copied to $EJBCA_HOME/addons/ed25519/. Nothing is downloaded; every
# file is checked against its .sha256 before use.
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=hsm-installer-lib.sh
source "${SCRIPT_DIR}/hsm-installer-lib.sh"

# ── Add-on constants ──────────────────────────────────────────────────────────
ADDON_NAME="Ed25519"
ADDON_ID="ed25519"
MODULE_NAME="com.devisefutures.ed25519"
PROVIDER_NAME="hsm-ed25519"
STARTUP_BEAN="HsmEd25519StartupBean"
LISTENER_JAR="hsm-ed25519-listener.jar"

MODULE_FILES=("hsm-ed25519-provider.jar" "jna-5.18.1.jar" "module.xml")
PLUGIN_FILES=("${LISTENER_JAR}" "plugin-build.xml")
PLUGIN_PROPS="${ADDON_ID}.properties"

REQUIRED_KEYS=(EJBCA_HOME WILDFLY_HOME WILDFLY_USER HTTP_PORT EJBCA_VERSION ED25519_VERSION)
# Extra keys for migrate-from-7x (database access, library, service).
MIGRATE_KEYS=(WILDFLY_SERVICE DB_NAME DB_USER DB_PASS P11_LIB_FILE)

show_usage() { sed -n '/^# Usage:/,/^# ===/p' "$0" | grep -v '^# ===' | sed 's/^# \{0,1\}//'; }

# ── Arguments ─────────────────────────────────────────────────────────────────
CONFIG=""; MODE=""; ASSUME_YES=false; SET_PINS=false   # ASSUME_YES is read by ask() in hsm-installer-lib.sh
while [[ $# -gt 0 ]]; do
    case "$1" in
        --config)   CONFIG="${2:?--config needs a value}"; shift 2 ;;
        --mode)     MODE="${2:?--mode needs a value}";     shift 2 ;;
        --set-pins) SET_PINS=true; shift ;;
        --yes)      ASSUME_YES=true; shift ;;
        --help|-h)  show_usage; exit 0 ;;
        *) die "Unknown option: $1 (see --help)" ;;
    esac
done
[[ -n "$CONFIG" ]] || die "--config is required (see --help)."
[[ -n "$MODE"   ]] || die "--mode is required (see --help)."
if $SET_PINS; then
    [[ "$MODE" == "migrate-from-7x" ]] || die "--set-pins is only valid with --mode migrate-from-7x."
    ! $ASSUME_YES || die "--set-pins asks for HSM PINs at the terminal; it cannot be combined with --yes."
fi

# ── Derived paths (after config) ──────────────────────────────────────────────
set_paths() {
    MODULE_DIR="${WILDFLY_HOME}/modules/$(echo "$MODULE_NAME" | tr '.' '/')/main"
    PLUGIN_DIR="${EJBCA_HOME}/addons/${ADDON_ID}"
    PLUGIN_PROPS_DEST="${EJBCA_HOME}/conf/plugins/${PLUGIN_PROPS}"
}

# =============================================================================
# MODE pre-deploy
# =============================================================================
pre_deploy() {
    log_step "Checks"
    verify_sidecars "$SCRIPT_DIR" "${MODULE_FILES[@]}" "${PLUGIN_FILES[@]}" "$PLUGIN_PROPS"
    if [[ -f "${SCRIPT_DIR}/VERSION" ]]; then
        local shipped; shipped="$(tr -d ' \r\n' < "${SCRIPT_DIR}/VERSION")"
        [[ "$shipped" == "$ED25519_VERSION" ]] \
            || die "Add-on files in ${SCRIPT_DIR} are release ${shipped}; config ED25519_VERSION is ${ED25519_VERSION}."
        log_ok "Add-on release ${shipped}."
    fi

    [[ -f "${EJBCA_HOME}/build.xml" ]] || die "No EJBCA source at ${EJBCA_HOME}."
    local found; found="$(ejbca_source_version "$EJBCA_HOME")"
    [[ "$found" == "$EJBCA_VERSION" ]] \
        || die "EJBCA source is ${found:-unknown}; config EJBCA_VERSION is ${EJBCA_VERSION}."
    [[ "$(release_ejbca_code "$ED25519_VERSION")" == "$(ejbca_version_code "$EJBCA_VERSION")" ]] \
        || die "Add-on ${ED25519_VERSION} is not built for EJBCA ${EJBCA_VERSION} (expected ?.$(ejbca_version_code "$EJBCA_VERSION").x)."
    log_ok "EJBCA source version ${found}."
    ejbca_has_plugin_hook "$EJBCA_HOME" \
        || die "EJBCA source at ${EJBCA_HOME} has no add-on plugin hook."
    log_ok "EJBCA plugin hook present."

    [[ -x "${WILDFLY_HOME}/bin/jboss-cli.sh" ]] || die "No WildFly at ${WILDFLY_HOME}."
    wf_running || die "WildFly is not running. Start it first (systemctl start wildfly-standalone)."
    log_ok "WildFly running."
    wf_cli '/subsystem=elytron/aggregate-providers=combined-providers:read-resource' >/dev/null 2>&1 \
        || die "Elytron aggregate-providers 'combined-providers' not found in standalone.xml - unexpected WildFly configuration."

    log_step "Plan"
    cat <<EOF
  Add-on            ${ADDON_NAME} ${ED25519_VERSION} (for EJBCA ${EJBCA_VERSION})
  WildFly module    ${MODULE_DIR}/  <- ${MODULE_FILES[*]}
  standalone.xml    (jboss-cli, then reload)
                      ee global-modules            += ${MODULE_NAME}
                      elytron provider-loader      ${PROVIDER_NAME} (module ${MODULE_NAME})
                      elytron combined-providers   += ${PROVIDER_NAME}
  EJBCA plugin      ${PLUGIN_DIR}/  <- ${PLUGIN_FILES[*]}
                    ${PLUGIN_PROPS_DEST}
  Next step         ant deployear (the build includes the add-on from now on)
EOF
    ask "Proceed?" || { log_info "Aborted."; exit 0; }

    log_step "WildFly module"
    mkdir -p "$MODULE_DIR"
    local f
    for f in "${MODULE_FILES[@]}"; do
        cp "${SCRIPT_DIR}/${f}" "${MODULE_DIR}/${f}"
    done
    chown -R "${WILDFLY_USER}:${WILDFLY_USER}" "${WILDFLY_HOME}/modules/com/devisefutures"
    log_ok "Module installed: ${MODULE_DIR}"

    log_step "standalone.xml"
    local changed=false
    if wf_global_module_names | grep -qx "$MODULE_NAME"; then
        log_info "Global module ${MODULE_NAME} already present."
    else
        wf_cli "/subsystem=ee:list-add(name=global-modules,value={name=${MODULE_NAME},slot=main})" >/dev/null \
            || die "Failed to add global module ${MODULE_NAME}."
        log_ok "Global module added."; changed=true
    fi
    if wf_cli "/subsystem=elytron/provider-loader=${PROVIDER_NAME}:read-resource" >/dev/null 2>&1; then
        log_info "Provider-loader ${PROVIDER_NAME} already present."
    else
        wf_cli "/subsystem=elytron/provider-loader=${PROVIDER_NAME}:add(module=${MODULE_NAME})" >/dev/null \
            || die "Failed to add provider-loader ${PROVIDER_NAME}."
        log_ok "Provider-loader added."; changed=true
    fi
    if wf_cli '/subsystem=elytron/aggregate-providers=combined-providers:read-attribute(name=providers)' \
            | grep -q "\"${PROVIDER_NAME}\""; then
        log_info "${PROVIDER_NAME} already in combined-providers."
    else
        wf_cli "/subsystem=elytron/aggregate-providers=combined-providers:list-add(name=providers,value=${PROVIDER_NAME})" >/dev/null \
            || die "Failed to add ${PROVIDER_NAME} to combined-providers."
        log_ok "Added to combined-providers."; changed=true
    fi
    if $changed; then wf_reload; fi

    log_step "EJBCA build plugin"
    mkdir -p "$PLUGIN_DIR" "$(dirname "$PLUGIN_PROPS_DEST")"
    if [[ "$(readlink -f "$SCRIPT_DIR")" == "$(readlink -f "$PLUGIN_DIR")" ]]; then
        log_info "Plugin files already in place (shipped with the EJBCA source)."
    else
        for f in "${PLUGIN_FILES[@]}"; do
            cp "${SCRIPT_DIR}/${f}" "${PLUGIN_DIR}/${f}"
        done
    fi
    sed "s#@EJBCA_HOME@#${EJBCA_HOME}#g" "${SCRIPT_DIR}/${PLUGIN_PROPS}" > "$PLUGIN_PROPS_DEST"
    grep -q "^plugin.ejbca.ant.file=${PLUGIN_DIR}/plugin-build.xml$" "$PLUGIN_PROPS_DEST" \
        || die "Unexpected content in ${PLUGIN_PROPS_DEST}."
    log_ok "Plugin installed: ${PLUGIN_DIR}, ${PLUGIN_PROPS_DEST}"

    echo ""
    log_ok "${ADDON_NAME} pre-deploy complete."
    log_info "Next: build and deploy EJBCA (cd ${EJBCA_HOME} && ant clean deployear),"
    log_info "      then: $0 --config ${CONFIG} --mode verify"
}

# =============================================================================
# MODE verify
# =============================================================================
FAILS=0
check() {   # check "description" command [args...]  (command may be a function)
    local desc="$1"; shift
    if "$@" >/dev/null 2>&1; then log_ok "$desc"; else log_err "$desc"; FAILS=$((FAILS+1)); fi
}

has_global_module()   { wf_global_module_names | grep -qx "$MODULE_NAME"; }
has_provider_loader() { wf_cli "/subsystem=elytron/provider-loader=${PROVIDER_NAME}:read-resource"; }
ear_has_entry()       { unzip -l "$EAR" | awk '{print $4}' | grep -qx "$1"; }
ear_file_contains()   { unzip -p "$EAR" "$1" | grep -qF "$2"; }
bean_registered()     { grep "$STARTUP_BEAN" "$SERVER_LOG" | grep -q 'registration: true'; }

verify() {
    EAR="${EJBCA_HOME}/dist/ejbca.ear"
    SERVER_LOG="${WILDFLY_HOME}/standalone/log/server.log"
    local dep="${WILDFLY_HOME}/standalone/deployments"

    log_step "WildFly"
    local f
    for f in "${MODULE_FILES[@]}"; do
        check "Module file ${f}" test -f "${MODULE_DIR}/${f}"
    done
    check "WildFly running"                        wf_running
    check "Global module ${MODULE_NAME}"           has_global_module
    check "Provider-loader ${PROVIDER_NAME}"       has_provider_loader

    log_step "EAR"
    check "Plugin declared (${PLUGIN_PROPS_DEST})" test -f "$PLUGIN_PROPS_DEST"
    check "EAR built (${EAR})"                     test -f "$EAR"
    check "Listener at EAR root"                   ear_has_entry "$LISTENER_JAR"
    check "Listener in EAR lib/"                   ear_has_entry "lib/${LISTENER_JAR}"
    check "application.xml declares the listener"  ear_file_contains META-INF/application.xml "<ejb>${LISTENER_JAR}</ejb>"
    check "jboss-deployment-structure.xml module"  ear_file_contains META-INF/jboss-deployment-structure.xml "module name=\"${MODULE_NAME}\""
    check "EAR deployed (ejbca.ear.deployed)"      test -f "${dep}/ejbca.ear.deployed"
    check "No failed deployment marker"            test ! -f "${dep}/ejbca.ear.failed"

    log_step "Runtime"
    check "${STARTUP_BEAN} registration: true (server.log)" bean_registered
    check "EJBCA healthcheck ALLOK"                ejbca_health_ok

    echo ""
    if [[ $FAILS -eq 0 ]]; then
        log_ok "${ADDON_NAME} add-on verified."
    else
        die "${FAILS} check(s) failed. See ${SERVER_LOG}"
    fi
}

# =============================================================================
# MODE migrate-from-7x
# =============================================================================
# EJBCA CE 9.x no longer contains PKCS11CryptoToken: after the standard upgrade
# from 7.x those tokens load as NullCryptoToken (offline, no keys). This mode
# converts them to HsmEd25519CryptoToken, which serves RSA/EC keys through
# SunPKCS11 and Ed25519 keys (including the 7.x fork's layout) through its own
# PKCS#11 wrapper. Only the token type and the library change; slot, PIN and
# name are kept. The 7.x auto-activation PIN is in an old format the converted
# token cannot use, so each token must be activated once (--set-pins, or the
# Admin UI); EJBCA then stores the PIN in the current format.

NEW_TOKEN_TYPE="HsmEd25519CryptoToken"
OLD_TOKEN_TYPE="PKCS11CryptoToken"
KNOWN_TOKEN_TYPES="SoftCryptoToken PKCS11CryptoToken HsmEd25519CryptoToken HsmSmCryptoToken"

DB_DEFAULTS=""
db_open() {     # credentials in a private file, not on the command line
    DB_DEFAULTS="$(mktemp)"
    chmod 600 "$DB_DEFAULTS"
    printf '[client]\nuser=%s\npassword=%s\n' "$DB_USER" "$DB_PASS" > "$DB_DEFAULTS"
    trap 'rm -f "$DB_DEFAULTS"' EXIT
}
db()      { mysql --defaults-extra-file="$DB_DEFAULTS" -N -B -r "$DB_NAME" "$@"; }
db_dump() { mysqldump --defaults-extra-file="$DB_DEFAULTS" --single-transaction "$DB_NAME" "$@"; }

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
    hex="$(db -e "SELECT HEX(data) FROM GlobalConfigurationData WHERE configurationId='UPGRADE'" 2>/dev/null)" || return 1
    [[ -n "$hex" ]] || return 1
    val="$(perl -e "$UPGVAL_PL" "$key" "$hex")" || return 1
    [[ "$val" == B64:* ]] && val="$(printf '%s' "${val#B64:}" | base64 -d 2>/dev/null || true)"
    printf '%s\n' "$val"
}

# Decoded tokenProps (Java properties) of a token id, and one property of it.
token_props() { db -e "SELECT tokenProps FROM CryptoTokenData WHERE id=$1" | base64 -d; }
prop()        { sed -n "s/^${2}=//p" <<<"$1" | head -1; }

# EJBCA CLI (runs on this host against the local WildFly).
ejbca_cli() { "${EJBCA_HOME}/bin/ejbca.sh" "$@"; }
token_status() {   # active | offline | unknown (from "cryptotoken list")
    local line
    line="$(ejbca_cli cryptotoken list 2>/dev/null | grep -F "($1)" | head -1)" || true
    case "$line" in
        *", active,"*)  echo active ;;
        *", offline,"*) echo offline ;;
        *)              echo unknown ;;
    esac
}
token_aliases() {  # one alias per line, from "cryptotoken listkeys"
    ejbca_cli cryptotoken listkeys --token "$1" 2>/dev/null \
        | awk -F'\t' '/^ [^ ]/ && NF>=2 && $0 !~ /ALIAS\t/ {sub(/^ /,"",$1); print $1}'
}

wf_wait_started() {   # after systemctl start: boot (incl. ejbca.ear) complete
    local max=960 i=0 dep="${WILDFLY_HOME}/standalone/deployments"
    log_info "Waiting for WildFly and EJBCA (first start can take several minutes)..."
    until wf_running; do
        [[ -f "${dep}/ejbca.ear.failed" ]] && die "EJBCA deployment failed: $(head -c 1000 "${dep}/ejbca.ear.failed")"
        sleep 5; i=$((i+5))
        [[ $i -ge $max ]] && die "WildFly not running after ${max}s. Check ${WILDFLY_HOME}/standalone/log/server.log"
    done
    [[ -f "${dep}/ejbca.ear.deployed" ]] || die "ejbca.ear is not deployed. Check ${WILDFLY_HOME}/standalone/log/server.log"
    log_ok "WildFly running, ejbca.ear deployed (${i}s)."
}

migrate_from_7x() {
    local dep="${WILDFLY_HOME}/standalone/deployments"

    log_step "Checks"
    load_config "$CONFIG" "${MIGRATE_KEYS[@]}"
    command -v mysql >/dev/null || die "mysql client not found."
    [[ "$P11_LIB_FILE" =~ ^/[A-Za-z0-9._/-]+$ ]] || die "P11_LIB_FILE has characters this script does not write into token properties: ${P11_LIB_FILE}"
    [[ -f "$P11_LIB_FILE" ]] || die "HSM library not found: ${P11_LIB_FILE}"
    [[ -x "${EJBCA_HOME}/bin/ejbca.sh" ]] || die "EJBCA CLI not found: ${EJBCA_HOME}/bin/ejbca.sh"
    wf_running || die "WildFly is not running. Start it first (systemctl start ${WILDFLY_SERVICE})."
    [[ -f "${dep}/ejbca.ear.deployed" ]] || die "ejbca.ear is not deployed."
    has_global_module || die "The ${ADDON_NAME} add-on is not installed in WildFly (run install-ejbca.sh with --addon ${ADDON_ID})."
    unzip -l "${EJBCA_HOME}/dist/ejbca.ear" 2>/dev/null | awk '{print $4}' | grep -qx "$LISTENER_JAR" \
        || die "The deployed EAR does not contain the ${ADDON_NAME} add-on."
    log_ok "WildFly running, EJBCA deployed with the ${ADDON_NAME} add-on."

    db_open
    db -e "SELECT 1" >/dev/null || die "Cannot connect to database ${DB_NAME} as ${DB_USER}."
    local upg post
    upg="$(upgrade_value upgradedToVersion || true)"
    post="$(upgrade_value postUpgradedToVersion || true)"
    [[ "$upg" == "$EJBCA_VERSION" ]] \
        || die "Database is not upgraded to EJBCA ${EJBCA_VERSION} (upgradedToVersion: '${upg}'). Run the standard EJBCA upgrade first (install-ejbca.sh --mode upgrade-from-7x)."
    [[ "${post%%.*}" == "${EJBCA_VERSION%%.*}" ]] \
        || die "Post-upgrade has not run (postUpgradedToVersion: '${post}'). Run it first: Admin UI > System Upgrade, or: cd ${EJBCA_HOME} && ant upgrade"
    log_ok "Database upgraded to ${upg}, post-upgrade done (${post})."

    # Tokens to convert, and a check of each one
    local rows id name type props lib ltype slot
    local i
    local -a conv_ids=() conv_names=() conv_new=() conv_lines=() others=()
    rows="$(db -e "SELECT id, tokenType, tokenName FROM CryptoTokenData ORDER BY tokenName")"
    while IFS=$'\t' read -r id type name; do
        [[ -n "$id" ]] || continue
        case " ${KNOWN_TOKEN_TYPES} " in
            *" ${type} "*) ;;
            *) others+=("${name} (${type})") ;;
        esac
        [[ "$type" == "$OLD_TOKEN_TYPE" ]] || continue
        props="$(token_props "$id")" || die "Token '${name}' (${id}): tokenProps cannot be decoded."
        lib="$(prop "$props" sharedLibrary)"
        ltype="$(prop "$props" slotLabelType)"
        slot="$(prop "$props" slotLabelValue)"
        [[ "$(basename "$lib")" == libcs* ]] \
            || die "Token '${name}' uses library '${lib}', not a Utimaco library. This mode only converts Utimaco tokens; nothing was changed."
        [[ "$ltype" == "SLOT_NUMBER" && "$slot" =~ ^[0-9]+$ ]] \
            || die "Token '${name}' refers to its slot by ${ltype:-?} '${slot}'. ${NEW_TOKEN_TYPE} needs a slot number (SLOT_NUMBER); nothing was changed."
        conv_ids+=("$id"); conv_names+=("$name")
        conv_new+=("$(printf '%s\n' "$props" | awk -v l="$P11_LIB_FILE" '/^sharedLibrary=/{print "sharedLibrary=" l; next} {print}' | base64 -w0)")
        conv_lines+=("$(printf '    %-24s slot %-3s %s -> %s' "$name" "$slot" "$lib" "$P11_LIB_FILE")")
    done <<<"$rows"

    log_step "Plan"
    if [[ ${#conv_ids[@]} -eq 0 ]]; then
        log_info "No ${OLD_TOKEN_TYPE} left to convert."
    else
        echo "  Convert ${OLD_TOKEN_TYPE} -> ${NEW_TOKEN_TYPE} (slot and PIN kept, library changed):"
        printf '%s\n' "${conv_lines[@]}"
        echo "  Backup of CryptoTokenData before the change: /root/ejbca-cryptotokens-<date>.sql"
        echo "  WildFly is stopped during the change and started again (EJBCA keeps tokens in memory)."
    fi
    if [[ ${#others[@]} -gt 0 ]]; then
        log_warn "Left unchanged (type not handled by this add-on): ${others[*]}"
    fi
    if $SET_PINS; then
        echo "  Then: for each offline ${NEW_TOKEN_TYPE}, ask for its PIN (auto-activation) and test every key."
    else
        echo "  Then: activate each converted token once in the Admin UI (or run again with --set-pins)."
    fi
    if [[ ${#conv_ids[@]} -gt 0 ]]; then
        ask "Proceed?" || { log_info "Aborted."; exit 0; }

        log_step "Convert"
        local backup; backup="/root/ejbca-cryptotokens-$(date +%Y%m%d-%H%M%S).sql"
        ( umask 077; db_dump CryptoTokenData > "$backup" ) || die "Backup of CryptoTokenData failed; nothing was changed."
        log_ok "Backup: ${backup}"

        log_info "Stopping WildFly..."
        systemctl stop "$WILDFLY_SERVICE"
        ! wf_running || die "WildFly is still running; nothing was changed."

        local new got
        for i in "${!conv_ids[@]}"; do
            new="${conv_new[$i]}"
            [[ "$new" =~ ^[A-Za-z0-9+/=]+$ ]] || die "Internal error encoding properties of '${conv_names[$i]}'."
            db -e "UPDATE CryptoTokenData SET tokenType='${NEW_TOKEN_TYPE}', tokenProps='${new}', rowVersion=rowVersion+1 WHERE id=${conv_ids[$i]} AND tokenType='${OLD_TOKEN_TYPE}'"
            got="$(db -e "SELECT tokenType FROM CryptoTokenData WHERE id=${conv_ids[$i]}")"
            [[ "$got" == "$NEW_TOKEN_TYPE" ]] \
                || die "Token '${conv_names[$i]}' was not converted. Restore with: systemctl stop ${WILDFLY_SERVICE}; mysql ${DB_NAME} < ${backup}"
            [[ "$(prop "$(token_props "${conv_ids[$i]}")" sharedLibrary)" == "$P11_LIB_FILE" ]] \
                || die "Token '${conv_names[$i]}': library not updated. Restore with: mysql ${DB_NAME} < ${backup}"
            log_ok "Converted: ${conv_names[$i]}"
        done

        log_info "Starting WildFly..."
        systemctl start "$WILDFLY_SERVICE"
        wf_wait_started
    fi

    # Tokens of the new type that are offline (converted now or earlier)
    local -a ed_ids=() ed_names=()
    rows="$(db -e "SELECT id, tokenName FROM CryptoTokenData WHERE tokenType='${NEW_TOKEN_TYPE}' ORDER BY tokenName")"
    while IFS=$'\t' read -r id name; do
        [[ -n "$id" ]] || continue
        ed_ids+=("$id"); ed_names+=("$name")
    done <<<"$rows"

    if ! $SET_PINS; then
        echo ""
        log_ok "Migration of crypto tokens complete."
        local offline=()
        for i in "${!ed_ids[@]}"; do
            [[ "$(token_status "${ed_ids[$i]}")" == "active" ]] || offline+=("${ed_names[$i]}")
        done
        if [[ ${#offline[@]} -gt 0 ]]; then
            log_warn "Not active yet: ${offline[*]}"
            log_info "Activate each of them once in the Admin UI (Crypto Tokens > Activate, with the HSM PIN)."
            log_info "EJBCA then saves the auto-activation PIN again and they come up active on every restart."
            log_info "Or run: $0 --config ${CONFIG} --mode migrate-from-7x --set-pins"
        fi
        log_info "Then: $0 --config ${CONFIG} --mode verify"
        return 0
    fi

    log_step "PINs and key tests"
    local status alias failed=0 tested=0 summary=()
    for i in "${!ed_ids[@]}"; do
        id="${ed_ids[$i]}"; name="${ed_names[$i]}"
        status="$(token_status "$id")"
        if [[ "$status" != "active" ]]; then
            echo ""
            if ! ask "Token '${name}' is ${status}. Enter its HSM PIN now?"; then
                summary+=("${name}: skipped (${status})"); continue
            fi
            log_info "The PIN is asked twice by the EJBCA CLI and stored as the token's auto-activation PIN."
            if ! ejbca_cli cryptotoken setpin --token "$name" --update; then
                summary+=("${name}: setting the PIN failed"); failed=$((failed+1)); continue
            fi
            status="$(token_status "$id")"
            if [[ "$status" != "active" ]]; then
                # A wrong stored PIN would be retried at every start: remove it.
                ejbca_cli cryptotoken setpin --token "$name" --remove >/dev/null 2>&1 || true
                log_err "Token '${name}' is still ${status} (wrong PIN or HSM not reachable). Its auto-activation PIN was removed."
                summary+=("${name}: NOT active - PIN removed, activate in the Admin UI"); failed=$((failed+1)); continue
            fi
            log_ok "Token '${name}' active."
        fi
        local t_ok=0 t_fail=0
        while IFS= read -r alias; do
            [[ -n "$alias" ]] || continue
            local out
            out="$(ejbca_cli cryptotoken testkey --token "$name" --alias "$alias" 2>&1 || true)"
            if grep -q "tested successfully" <<<"$out"; then
                log_ok "  ${name} / ${alias}"; t_ok=$((t_ok+1))
            else
                log_err "  ${name} / ${alias}: test FAILED: $(grep -v '^\s*$' <<<"$out" | tail -1)"; t_fail=$((t_fail+1))
            fi
        done < <(token_aliases "$name")
        tested=$((tested+t_ok+t_fail)); failed=$((failed+t_fail))
        summary+=("${name}: active, ${t_ok} key(s) OK, ${t_fail} failed")
    done

    log_step "Summary"
    local s; for s in "${summary[@]}"; do echo "  ${s}"; done
    echo ""
    if [[ $failed -eq 0 ]]; then
        log_ok "Migration complete: ${#ed_ids[@]} token(s), ${tested} key(s) tested."
        log_info "Next: $0 --config ${CONFIG} --mode verify"
    else
        die "${failed} problem(s) - see the summary. Fix them in the Admin UI, or run this mode again with --set-pins."
    fi
}

# =============================================================================
main() {
    echo -e "\n${BOLD}HSM ${ADDON_NAME} add-on — mode ${MODE}${RST}"
    echo -e "────────────────────────────────────────────"
    require_root
    load_config "$CONFIG" "${REQUIRED_KEYS[@]}"
    set_paths
    case "$MODE" in
        pre-deploy)      pre_deploy ;;
        verify)          verify ;;
        migrate-from-7x) migrate_from_7x ;;
        *)               die "Unknown mode: ${MODE} (pre-deploy | verify | migrate-from-7x)" ;;
    esac
}

main