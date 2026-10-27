#!/bin/bash
# MainNet dry-run stack on the SAME host as TestNet (no new instance).
# Run as root on the host:  bash provision-mainnet.sh <release-dir>
# Idempotent. Never prints secrets. Leaves the MainNet app services STOPPED and DISABLED,
# and the pause file in place (paid route + /sign refuse with 503 even if started).
#
# Isolation from TestNet:
#  - Postgres: separate cluster 18/mainnet on 127.0.0.1:5434, database mandaterail_mainnet,
#    its own mr_* roles (cluster-local, so no name clash) and passwords.
#  - Redis: same redis-mr, db 1, key prefix mrm (REDIS_KEY_PREFIX), ACL users mrm_bridge /
#    mrm_console limited to ~mrm:* patterns (TestNet users can't match mrm:, and vice versa).
#  - Env: /etc/mandaterail/mainnet-*.env (root 0600); units mandaterail-mainnet-*;
#    code via its own symlink /opt/mandaterail/mainnet-current; data /var/lib/mandaterail-mainnet.
#  - Ports 127.0.0.1:8797 (demo-api) / 8800 (ac2-bridge) / 8798 (console);
#    hosts mr-mainnet-{api,bridge,console}.8-221-97-26.sslip.io (not linked from Pages).
set -euo pipefail
umask 077
R=${1:?release dir}
test -d "$R/packages/storage"
PG_PORT=5434; DB=mandaterail_mainnet; SEC=/root/.mr-mainnet-secrets; E=/etc/mandaterail
PAYER=${MAINNET_PAYER:?}; MERCHANT=${MAINNET_MERCHANT:?}; REQUESTER=${MAINNET_REQUESTER:?}
OPERATOR=JXPWXFXYO6RA546SZOD7YACKDEXVLAL2WWZ5S36Y47X5D4WWZJEQGXP5R4
install -d -m 0700 -o root -g root $SEC
for r in pg_owner pg_admin pg_reconcile pg_monitor pg_release pg_demo_api pg_console pg_bridge redis_bridge redis_console; do
  [ -s $SEC/$r ] || openssl rand -hex 24 > $SEC/$r
done
chmod 0600 $SEC/*

# 1. Postgres cluster
if ! pg_lsclusters -h | awk '{print $1" "$2}' | grep -qx "18 mainnet"; then
  pg_createcluster 18 mainnet -p $PG_PORT -- --auth-local=peer --auth-host=scram-sha-256 >/dev/null
  sed -i "s/^#\?listen_addresses.*/listen_addresses = 'localhost'/" /etc/postgresql/18/mainnet/postgresql.conf
fi
systemctl enable --now postgresql@18-mainnet >/dev/null 2>&1
PSQL="sudo -u postgres psql -X -q -p $PG_PORT -v ON_ERROR_STOP=1"
for i in $(seq 1 20); do $PSQL -d postgres -Atc 'select 1' >/dev/null 2>&1 && break; sleep 1; done
# zero database-wide / ALTER ROLE ALL settings before anything else
n=$($PSQL -d postgres -Atc "SELECT count(*) FROM pg_db_role_setting WHERE setrole=0")
[ "$n" = 0 ] || { echo "ABORT: $n database-wide settings on the mainnet cluster"; exit 1; }
# owner role + DB (password via psql backtick, never on a command line)
if ! $PSQL -d postgres -Atc "SELECT 1 FROM pg_database WHERE datname='$DB'" | grep -q 1; then
  install -m 0640 -o root -g postgres /dev/null /tmp/mrm-pw && cat $SEC/pg_owner > /tmp/mrm-pw
  $PSQL -d postgres <<SQL
\set pw \`cat /tmp/mrm-pw\`
DO \$\$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='mr_owner') THEN CREATE ROLE mr_owner LOGIN; END IF; END \$\$;
ALTER ROLE mr_owner LOGIN PASSWORD :'pw';
CREATE DATABASE $DB OWNER mr_owner;
REVOKE ALL ON DATABASE postgres FROM PUBLIC;
SQL
  shred -u /tmp/mrm-pw
fi
n=$($PSQL -d $DB -Atc "SELECT count(*) FROM pg_db_role_setting WHERE setrole=0 AND setdatabase IN (0,(SELECT oid FROM pg_database WHERE datname='$DB'))")
echo "mainnet db-wide/ALTER ROLE ALL settings before migrate: $n"; [ "$n" = 0 ] || exit 1

url() { printf 'postgres://%s:%s@127.0.0.1:%s/%s' "$1" "$(cat $SEC/$2)" $PG_PORT $DB; }
w() { install -m 0600 -o root -g root /dev/null "$1"; cat > "$1"; }

# 2. first migrate (as mr_owner while it can still log in; afterwards via mr_admin + window)
if ! $PSQL -d $DB -Atc "SELECT 1 FROM pg_class WHERE relname='mr_schema'" | grep -q 1; then
  w $E/mainnet-state-migrate.env <<X
MIGRATE_DATABASE_URL=$(url mr_owner pg_owner)
NETWORK=mainnet
ALLOW_MAINNET=1
X
  (cd $R && TSX_DISABLE_CACHE=1 STATE_ENV_FILE=$E/mainnet-state-migrate.env pnpm --silent --filter @mandaterail/storage migrate)
fi

# 3. role SQL (creates mr_admin/reconcile/monitor/release, owner -> NOLOGIN). Passwords via backticks.
install -m 0644 $R/deploy/sql/t11-mr-reconcile-role.sql /tmp/mrm-role.sql
install -d -m 0750 -o root -g postgres /tmp/mrm-pw.d
for r in pg_admin pg_reconcile pg_monitor pg_release; do install -m 0640 -o root -g postgres $SEC/$r /tmp/mrm-pw.d/$r; done
{ if ! $PSQL -d $DB -Atc "SELECT 1 FROM pg_roles WHERE rolname='mr_admin'" | grep -q 1; then
    printf '\\set admin_pw `cat /tmp/mrm-pw.d/pg_admin`\n\\set pw `cat /tmp/mrm-pw.d/pg_reconcile`\n\\set mon_pw `cat /tmp/mrm-pw.d/pg_monitor`\n\\set rel_pw `cat /tmp/mrm-pw.d/pg_release`\n'
  fi
  printf '\\i /tmp/mrm-role.sql\n'; } > /tmp/mrm-wrap.sql; chmod 0644 /tmp/mrm-wrap.sql
$PSQL -d $DB -a -f /tmp/mrm-wrap.sql > /root/mainnet-role-sql.txt 2>&1 || { rm -rf /tmp/mrm-pw.d; echo "role SQL failed, see /root/mainnet-role-sql.txt"; exit 1; }
rm -rf /tmp/mrm-pw.d /tmp/mrm-wrap.sql /tmp/mrm-role.sql
grep -q "PASSWORD '" /root/mainnet-role-sql.txt && { echo "ABORT: password echoed in evidence"; shred -u /root/mainnet-role-sql.txt; exit 1; } || true

# 4. app roles LOGIN + password
install -d -m 0750 -o root -g postgres /tmp/mrm-pw.d
for r in pg_demo_api pg_console pg_bridge; do install -m 0640 -o root -g postgres $SEC/$r /tmp/mrm-pw.d/$r; done
$PSQL -d $DB <<'SQL'
\set a `cat /tmp/mrm-pw.d/pg_demo_api`
\set c `cat /tmp/mrm-pw.d/pg_console`
\set b `cat /tmp/mrm-pw.d/pg_bridge`
ALTER ROLE mr_demo_api LOGIN PASSWORD :'a';
ALTER ROLE mr_console LOGIN PASSWORD :'c';
ALTER ROLE mr_bridge LOGIN PASSWORD :'b';
SQL
rm -rf /tmp/mrm-pw.d

# 5. env files
w $E/mainnet-state-migrate.env <<X
MIGRATE_DATABASE_URL=$(url mr_admin pg_admin)
MIGRATE_SET_ROLE=mr_owner
NETWORK=mainnet
ALLOW_MAINNET=1
X
RU() { printf 'redis://%s:%s@127.0.0.1:6379/1' "$1" "$(cat $SEC/$2)"; }
# demo-api uses no Redis keys (TestNet's mr_demo_api Redis user has none either): Postgres only.
w $E/mainnet-state-demo-api.env <<X
STATE_BACKEND=postgres
DATABASE_URL=$(url mr_demo_api pg_demo_api)
X
w $E/mainnet-state-bridge.env <<X
STATE_BACKEND=redis+postgres
DATABASE_URL=$(url mr_bridge pg_bridge)
REDIS_URL=$(RU mrm_bridge redis_bridge)
REDIS_KEY_PREFIX=mrm
X
w $E/mainnet-state-console.env <<X
STATE_BACKEND=redis+postgres
DATABASE_URL=$(url mr_console pg_console)
REDIS_URL=$(RU mrm_console redis_console)
REDIS_KEY_PREFIX=mrm
X
w $E/mainnet-state-reconcile.env <<X
DATABASE_URL=$(url mr_reconcile pg_reconcile)
NETWORK=mainnet
ALLOW_MAINNET=1
INDEXER_URL=https://mainnet-idx.algonode.cloud
X
w $E/mainnet-state-monitor.env <<X
DATABASE_URL=$(url mr_monitor pg_monitor)
NETWORK=mainnet
ALLOW_MAINNET=1
MONITOR_HEALTH_URLS=https://mr-mainnet-api.8-221-97-26.sslip.io/health,https://mr-mainnet-bridge.8-221-97-26.sslip.io/health,https://mr-mainnet-console.8-221-97-26.sslip.io/health
$(grep '^MONITOR_PAGER_' $E/state-monitor.env)
X
w $E/mainnet-state-release.env <<X
DATABASE_URL=postgres://mr_release@127.0.0.1:$PG_PORT/$DB
NETWORK=mainnet
ALLOW_MAINNET=1
INDEXER_URL=https://mainnet-idx.algonode.cloud
X
w $E/mainnet-common.env <<X
NODE_ENV=production
NETWORK=mainnet
ALLOW_MAINNET=1
USDC_ASA_ID=31566704
GOPLAUSIBLE_BASE_URL=https://facilitator.goplausible.xyz
FEE_PAYER=ZMFK2OI7ZBD2U27ISERZC4S6LKM6WMFJPZQ4MYNJDZ2VNBNMBA67RA22AA
CORS_ORIGINS=https://mandaterail.pages.dev
ALGOD_URL=https://mainnet-api.algonode.cloud
SPEND_CAP_PER_PAYMENT_USDC=1.00
SPEND_CAP_PER_DAY_USDC=5.00
MANDATERAIL_PAUSE_FILE=$E/mainnet-PAUSE
COREPACK_HOME=/opt/mandaterail/.corepack
X
w $E/mainnet-demo-api.env <<X
DEMO_API_HOST=127.0.0.1
DEMO_API_PORT=8797
MERCHANT_ADDRESS=$MERCHANT
PRICE_USDC=0.01
RECEIPTS_PATH=/var/lib/mandaterail-mainnet/receipts.json
OPERATOR_ATTESTATION_MODE=signed-challenge
OPERATOR_ALLOWLIST=$OPERATOR
OPERATOR_SIGNDATA_DOMAIN=mandaterail.pages.dev
X
w $E/mainnet-ac2-bridge.env <<X
AC2_BRIDGE_HOST=127.0.0.1
AC2_BRIDGE_PORT=8800
AC2_BRIDGE_TRUSTED_PROXY_HOPS=1
OPERATOR_ATTESTATION_MODE=signed-challenge
OPERATOR_ALLOWLIST=$OPERATOR
OPERATOR_SIGNDATA_DOMAIN=mandaterail.pages.dev
REQUESTER_ALLOWLIST=$REQUESTER
X
w $E/mainnet-console.env <<X
CONSOLE_HOST=127.0.0.1
CONSOLE_PORT=8798
CONSOLE_DATA_DIR=/var/lib/mandaterail-mainnet/console
AC2_BRIDGE_TRUSTED_PROXY_HOPS=1
OPERATOR_ATTESTATION_MODE=signed-challenge
OPERATOR_ALLOWLIST=$OPERATOR
OPERATOR_SIGNDATA_DOMAIN=mandaterail.pages.dev
X
# pause file: present => /paid/* and /sign answer 503. Remove only for the rehearsal / dry run.
install -m 0644 -o root -g root /dev/null $E/mainnet-PAUSE
install -d -m 0750 -o mandaterail -g mandaterail /var/lib/mandaterail-mainnet /var/lib/mandaterail-mainnet/console

# 6. Redis ACL users (db 1 via URL; keys mrm:* only). Appended once, then redis-mr restarted (AOF keeps TestNet state).
RC=/etc/redis-mr/redis.conf
if ! grep -q '^user mrm_bridge ' $RC; then
  cp -p $RC $RC.bak-pre-mainnet
  CMDS='resetchannels -@all +@read +@write +eval +evalsha +ping +auth +hello +client|setname +select -@dangerous +script|load +script|exists'
  { printf 'user mrm_bridge on >%s resetkeys ~mrm:ch:{mandaterail-ac2-bridge}:* ~mrm:rl:{ac2-bridge:sign}:* ~mrm:rl:{ac2-bridge:challenge}:* %s\n' "$(cat $SEC/redis_bridge)" "$CMDS"
    printf 'user mrm_console on >%s resetkeys ~mrm:ch:{mandaterail-console}:* ~mrm:rl:{console:operator}:* %s\n' "$(cat $SEC/redis_console)" "$CMDS"; } >> $RC
  systemctl restart redis-mr
fi

# 7. code symlink + units (installed, NOT enabled, NOT started)
ln -sfn "$R" /opt/mandaterail/mainnet-current
for s in demo-api:demo-api:demo-api ac2-bridge:ac2-bridge:bridge console:console:console; do
  IFS=: read -r u env st <<<"$s"
  cat > /etc/systemd/system/mandaterail-mainnet-$u.service <<U
[Unit]
Description=MandateRail MAINNET dry-run $u
After=network-online.target
Wants=network-online.target
[Service]
User=mandaterail
Group=mandaterail
WorkingDirectory=/opt/mandaterail/mainnet-current/apps/$u
EnvironmentFile=$E/mainnet-common.env
EnvironmentFile=$E/mainnet-$env.env
EnvironmentFile=$E/mainnet-state-$st.env
Environment=STATE_ENV_FILE=/dev/null
Environment=TSX_DISABLE_CACHE=1
ExecStart=/usr/bin/node /opt/mandaterail/mainnet-current/node_modules/tsx/dist/cli.mjs src/index.ts
Restart=on-failure
RestartSec=5
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/var/lib/mandaterail-mainnet
U
  chmod 0644 /etc/systemd/system/mandaterail-mainnet-$u.service
done
for k in monitor reconcile; do
  sed -e "s#/etc/mandaterail/state-$k.env#$E/mainnet-state-$k.env#" -e "s#/opt/mandaterail/current#/opt/mandaterail/mainnet-current#g" \
      -e "s#^Description=MandateRail#Description=MandateRail MAINNET#" -e "s#^SyslogIdentifier=mandaterail-#SyslogIdentifier=mandaterail-mainnet-#" \
      "$R/deploy/systemd/mandaterail-$k.service" > /etc/systemd/system/mandaterail-mainnet-$k.service
  sed -e "s#mandaterail-$k.service#mandaterail-mainnet-$k.service#" "$R/deploy/systemd/mandaterail-$k.timer" > /etc/systemd/system/mandaterail-mainnet-$k.timer
  chmod 0644 /etc/systemd/system/mandaterail-mainnet-$k.{service,timer}
done
systemctl daemon-reload
echo "provisioned: services/timers installed but NOT enabled; pause file $E/mainnet-PAUSE present"
