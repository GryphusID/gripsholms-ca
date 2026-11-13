# Installing EJBCA with the Ed25519 HSM add-on

This repository contains EJBCA Community Edition with two additions:

- **A plugin hook in the build**, so add-ons can be built into the EJBCA EAR.
- **The Ed25519 add-on** in `addons/ed25519/`: Ed25519 keys and signatures on a
  Utimaco CryptoServer HSM through PKCS#11. Its release is in `addons/ed25519/VERSION`.

An add-on is only built in when it is installed. Without it, this source builds a
plain EJBCA.

You can install in two ways:

- **[Automatic](#automatic-installation)**: two scripts do everything, driven by one config file.
- **[Manual](#manual-installation)**: Keyfactor's standard installation, plus a few extra steps.

Both give the same result. To move an existing EJBCA 7.x instance to this version, see
[Upgrade from EJBCA 7.x](#upgrade-from-ejbca-7x).

## Requirements

- Ubuntu 22.04 LTS (x86_64), root access, at least 4 GB RAM and 2 CPUs.
- The Utimaco PKCS#11 R3 library (`libcs_pkcs11_R3.so`) and its configuration file
  (`cs_pkcs11_R3.cfg`) installed and working. Both must be readable by the user that
  runs WildFly, and the `Logpath` in the configuration must be writable by it.
- A release tag of this repository, e.g. `2.963.1`. Tags follow
  `<generation>.<ejbca-code>.<patch>`: the middle number is the EJBCA version without
  dots, so `2.963.x` is EJBCA 9.6.3.

---

## Automatic installation

### 1. Get the two release files

From the release page of the tag you want to install, download:

- `fetch-bundle.sh`
- `ejbca-install.conf.sample`

### 2. Fill in the configuration

```bash
cp ejbca-install.conf.sample /root/ejbca-install.conf
chown root:root /root/ejbca-install.conf
chmod 600 /root/ejbca-install.conf
vi /root/ejbca-install.conf
```

Every value must be filled in: there are no defaults, and an empty value stops the
scripts before they change anything. The keys specific to this installation:

| Key | Value |
|-----|-------|
| `EJBCA_REPO` | This repository, as `owner/name` |
| `EJBCA_PATCHES_TAG` | The tag to install, e.g. `2.963.1` |
| `EJBCA_VERSION` | The EJBCA version of that tag, e.g. `9.6.3` |
| `ED25519_VERSION` | The add-on release in that tag (`addons/ed25519/VERSION`) |
| `P11_LIB_FILE` | Path of `libcs_pkcs11_R3.so` |
| `HSM_CFG_FILE` | Path of `cs_pkcs11_R3.cfg` |
| `PBE_ENCRYPTION_KEY` | Key that encrypts secrets in the database. Choose it once and never change it. |
| `KS_PASS`, `TS_PASS` | TLS keystore and truststore passwords, at least 6 characters |

The other keys are the usual installation values: hostname, ports, database
credentials, keystore and SuperAdmin passwords.

### 3. Build the installation bundle

```bash
chmod +x fetch-bundle.sh
./fetch-bundle.sh --config /root/ejbca-install.conf --out /opt/ejbca-bundle
```

This collects everything the installation needs into one folder, checksummed:
the EJBCA source with the add-on, WildFly, the JDBC driver and the OS packages.

### 4. Install

```bash
cd /opt/ejbca-bundle
./install-ejbca.sh --config /root/ejbca-install.conf --mode fresh --addon ed25519
```

The script prints its plan and asks for confirmation (`--yes` skips the question).
It then installs and configures everything, builds and deploys EJBCA with the
add-on, creates the ManagementCA and SuperAdmin, and finally verifies the add-on.
It stops at the first error.

The host must be clean: no existing WildFly, `/opt/ejbca` or `ejbca` database.

### 5. Log in and test

1. Import `/opt/ejbca/p12/superadmin.p12` into your browser (password: `SUPERADMIN_PASS`).
2. Open `https://<hostname>:8443/ejbca/adminweb/`.
3. Create a crypto token of type **Ed25519 HSM** on your HSM slot, and generate an
   Ed25519 key in it.

To check the add-on again at any time:

```bash
/opt/ejbca/addons/ed25519/install-ed25519.sh --config /root/ejbca-install.conf --mode verify
```

---

## Manual installation

Follow Keyfactor's
[EJBCA installation guide](https://docs.keyfactor.com/ejbca-software/latest/installation)
for Java, the database, WildFly and EJBCA itself. The steps below are the additions
and changes for this installation, in the order they fit into that guide.

### Step 1: WildFly service environment (when configuring WildFly)

Add to WildFly's JVM options (`bin/standalone.conf`), at the end of the file so they
always apply:

```
# PKCS#11 on Java 17+
JAVA_OPTS="$JAVA_OPTS --add-exports=jdk.crypto.cryptoki/sun.security.pkcs11.wrapper=ALL-UNNAMED"
# The first EJBCA deployment can exceed WildFly's default 300 s and would be rolled back
JAVA_OPTS="$JAVA_OPTS -Djboss.as.management.blocking.timeout=900"
```

Check that the heap settings from Keyfactor's guide are really applied
(`ps -o args= -C java | grep -o -- '-Xm[sx][^ ]*'`): the default `standalone.conf`
only sets them when `JAVA_OPTS` is empty.

Tell the Utimaco library where its configuration is. With the systemd service, add
to `/etc/sysconfig/wildfly-standalone.conf`:

```
CS_PKCS11_R3_CFG="/path/to/cs_pkcs11_R3.cfg"
```

Without this, the library looks for `/etc/utimaco/cs_pkcs11_R3.cfg`, and crypto token
creation fails with "Initialization failed".

Recommended: start WildFly only after the database, so EJBCA's datasource is
available at boot:

```bash
mkdir -p /etc/systemd/system/wildfly-standalone.service.d
printf '[Unit]\nAfter=mariadb.service\nWants=mariadb.service\n' \
  > /etc/systemd/system/wildfly-standalone.service.d/10-mariadb.conf
systemctl daemon-reload
```

### Step 2: EJBCA source (instead of Keyfactor's download)

Use this repository's tag instead of Keyfactor's EJBCA source:

```bash
mkdir -p /opt/ejbca
curl -fL https://api.github.com/repos/<owner>/<name>/tarball/<tag> \
  | tar -xz --strip-components=1 -C /opt/ejbca
```

Check it:

```bash
grep '^app.version.number=' /opt/ejbca/src/internal.properties   # EJBCA version
grep -c 'ejbca.jboss-ds.xml' /opt/ejbca/build.xml                  # 2 = plugin hook present
cat /opt/ejbca/addons/ed25519/VERSION                              # add-on release
```

### Step 3: `conf/` files (as in Keyfactor's guide)

Configure `conf/*.properties` as the guide describes. In `web.properties`, declare the
Utimaco library:

```
cryptotoken.p11.lib.1.name=Utimaco PKCS#11 R3
cryptotoken.p11.lib.1.file=/path/to/libcs_pkcs11_R3.so
```

### Step 4: Install the add-on (before `ant deployear`)

With WildFly running and `conf/` written, either run the add-on installer:

```bash
/opt/ejbca/addons/ed25519/install-ed25519.sh --config /root/ejbca-install.conf --mode pre-deploy
```

(it reads `EJBCA_HOME`, `WILDFLY_HOME`, `WILDFLY_USER`, `HTTP_PORT`, `EJBCA_VERSION` and
`ED25519_VERSION` from the config file), or do the same three steps by hand:

**4a. WildFly module**

```bash
cd /opt/ejbca/addons/ed25519
sha256sum -c *.sha256
M=$WILDFLY_HOME/modules/com/devisefutures/ed25519/main
mkdir -p $M
cp hsm-ed25519-provider.jar jna-5.18.1.jar module.xml $M/
chown -R wildfly:wildfly $WILDFLY_HOME/modules/com/devisefutures
```

**4b. WildFly configuration**

```bash
CLI="$WILDFLY_HOME/bin/jboss-cli.sh --connect"
$CLI '/subsystem=ee:list-add(name=global-modules,value={name=com.devisefutures.ed25519,slot=main})'
$CLI '/subsystem=elytron/provider-loader=hsm-ed25519:add(module=com.devisefutures.ed25519)'
$CLI '/subsystem=elytron/aggregate-providers=combined-providers:list-add(name=providers,value=hsm-ed25519)'
$CLI ':reload'
```

**4c. Activate the EJBCA build plugin**

```bash
sed 's#@EJBCA_HOME@#/opt/ejbca#g' /opt/ejbca/addons/ed25519/ed25519.properties \
  > /opt/ejbca/conf/plugins/ed25519.properties
```

From now on, every `ant deployear` builds the add-on into the EAR.

### Step 5: Build, deploy and install (as in Keyfactor's guide)

Continue with the guide: `ant deployear`, `ant runinstall`, `ant deploy-keystore`.
The build output shows `Plugins found!` and `HSM Ed25519 plugin: done`.

### Step 6: Verify

```bash
/opt/ejbca/addons/ed25519/install-ed25519.sh --config /root/ejbca-install.conf --mode verify
```

Or check by hand:

- `grep HsmEd25519StartupBean $WILDFLY_HOME/standalone/log/server.log` shows `registration: true`.
- `unzip -l /opt/ejbca/dist/ejbca.ear | grep hsm-ed25519-listener.jar` shows it at the root and under `lib/`.
- In the Admin UI, an Ed25519 HSM crypto token can be created and an Ed25519 key generated.

---

## Upgrade from EJBCA 7.x

The 7.x instance's database and TLS keystores are moved to a **new server**, which runs
EJBCA's standard upgrade. The 7.x server is not changed, so it stays available as a
fallback. Then the add-on converts the 7.x HSM crypto tokens, which EJBCA CE 9.x can no
longer load as they are.

### 1. On the 7.x server

1. Note the values the new server needs:
   ```bash
   grep -E '^(password\.encryption\.(key|count)|httpsserver\.password|java\.trustpassword)=' \
     <7.x EJBCA>/conf/*.properties
   ```
   If `password.encryption.count` is set, stop: that case is not supported.
2. **Stop WildFly for good.** Both servers use the same HSM keys; they must never run
   at the same time.
3. Dump the database (without `--databases`) and copy the TLS keystores:
   ```bash
   sudo mysqldump --single-transaction --routines --triggers ejbca | gzip > ejbca-7x.sql.gz
   ls <7.x WildFly>/standalone/configuration/keystore/   # keystore.jks/.p12, truststore.jks/.p12
   ```
4. Keep the 7.x `superadmin.p12`: you log in to the new server with it.

Copy the dump and the two keystores to the new server (e.g. to `/root/`).

### 2. Configuration

Use the same configuration file as for a new installation, with these values:

| Key | Value |
|-----|-------|
| `PBE_ENCRYPTION_KEY` | The 7.x `password.encryption.key`, or `default` if 7.x has none |
| `KS_PASS`, `TS_PASS` | The 7.x `httpsserver.password` and `java.trustpassword` |
| `EJBCA_HOSTNAME` | The 7.x hostname (its TLS certificate is reused) |
| `UPGRADE_DB_DUMP` | The dump, e.g. `/root/ejbca-7x.sql.gz` |
| `UPGRADE_TLS_KEYSTORE`, `UPGRADE_TLS_TRUSTSTORE` | The two 7.x keystores |
| `SUPERADMIN_PASS` | Leave empty (not used) |

The new server must reach the HSM, with the same slots and PINs as the 7.x server.

### 3. Upgrade

```bash
./fetch-bundle.sh --config /root/ejbca-install.conf --out /opt/ejbca-bundle
cd /opt/ejbca-bundle
./install-ejbca.sh --config /root/ejbca-install.conf --mode upgrade-from-7x --addon ed25519
```

This installs everything as for a new installation, but imports the 7.x database instead
of creating a ManagementCA and SuperAdmin. On its first start, EJBCA upgrades the
database; the script then installs the 7.x TLS keystores and runs EJBCA's post-upgrade.

### 4. Convert the HSM crypto tokens

```bash
/opt/ejbca/addons/ed25519/install-ed25519.sh --config /root/ejbca-install.conf --mode migrate-from-7x --set-pins
```

Every 7.x PKCS#11 crypto token becomes an *Ed25519 HSM* token with the R3 library; its
slot, keys and CAs stay the same. The script restarts WildFly, then asks for each token's
HSM PIN and tests every key. A backup of the token table is written to `/root/` first.

Without `--set-pins`, it only converts the tokens: then activate each one once in the
Admin UI (*Crypto Tokens → Activate*). Either way, this is needed once: EJBCA then stores
the PIN again and the token comes up active on every restart.

### 5. Verify

```bash
/opt/ejbca/addons/ed25519/install-ed25519.sh --config /root/ejbca-install.conf --mode verify
```

Log in with the 7.x `superadmin.p12`, check that the CAs are active, and issue a test
certificate and CRL from a CA on the HSM.

**Fallback:** until the new server issues certificates or CRLs, you can stop it and start
the 7.x server again. After that, the 7.x database lacks what the new server issued.

---

## After installation

- **Configuration changes** (`conf/*.properties`): rebuild with `ant clean deployear`
  as usual. The add-on is included automatically; nothing else to do.
- **Uninstall the add-on:** first delete every Ed25519 crypto token (and its CAs),
  then run `/opt/ejbca/addons/ed25519/uninstall-ed25519.sh --config /root/ejbca-install.conf`.
- **Keep safe:** the config file (it holds `PBE_ENCRYPTION_KEY`), `/opt/ejbca/p12/`,
  and regular database backups.