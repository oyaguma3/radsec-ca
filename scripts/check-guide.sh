#!/bin/bash
# 運用ガイド（docs/operations.md）の管理モードの手順を、compose で実際に流して確かめる（CI のジョブと手元の確かめ）。
#
# 確かめること: 導入（KEK・ピン・監査ログのディレクトリ）、共有のネットワークからの mTLS、ピンの入れ替えと SIGHUP、
# サーバー証明書の作り直しと SIGHUP、持ち込みの CA の登録（アップロード）と CRL の配布、内部のアドレスの拒否、グループの証明書、停止、
# 監査ログのファイル、バックアップと戻し、KEK の入れ替え。
#
# 手元で動かすときは sudo がなくてもよい（UID 65532 で読み書きできるよう、試験の間だけ権限を広げる）。
# compose のプロジェクト名を変えるので、ほかの compose とはぶつからない。
set -euo pipefail

cd "$(dirname "$0")/.."
export COMPOSE_PROJECT_NAME=ca-guide-check
export COMPOSE_FILE=compose.yaml:compose.managed.yaml
export PROVISIONER_SHARED_NETWORK=ca-guide-check-shared
WORK=$(mktemp -d)
CURL_IMAGE=curlimages/curl:8.17.0

fail() { echo "FAIL: $*" >&2; docker compose logs --no-color radsec-ca >&2 || true; exit 1; }
pass() { echo "ok: $*"; }

cleanup() {
	docker compose down -v --remove-orphans >/dev/null 2>&1 || true
	docker network rm "$PROVISIONER_SHARED_NETWORK" >/dev/null 2>&1 || true
	# UID 65532 が作ったファイルはコンテナの中から消す。
	docker run --rm -v "$PWD:/w" busybox:1.37.0 rm -rf /w/audit /w/secrets >/dev/null 2>&1 || true
	rm -rf .env "$WORK"
}
trap cleanup EXIT

[ ! -e .env ] && [ ! -e secrets ] && [ ! -e audit ] || { echo "the working tree already has .env, secrets or audit" >&2; exit 2; }

# UID 65532 に読ませ、書かせる。sudo があれば手順どおり chown し、なければ権限を広げる。
own() {
	if sudo -n true 2>/dev/null; then
		sudo chown -R 65532:65532 "$@"
	else
		chmod -R a+rX "$@"
		for p in "$@"; do
			if [ -d "$p" ]; then chmod a+rwx "$p"; fi
		done
	fi
}

# put <ファイル> は標準入力をファイルにその場で書く（chown の後は sudo が要る。動いているコンテナが同じファイルを見続けるよう、置き換えない）。
put() {
	if sudo -n true 2>/dev/null; then
		sudo tee "$1" >/dev/null
	else
		cat >"$1"
	fi
}

# 運用ガイド 2.1・2.2・3.1
cp .env.example .env
sed -i -e 's|^CA_ORG=.*|CA_ORG=Guide Org|' -e 's|^CA_BIND_ADDR=.*|CA_BIND_ADDR=127.0.0.1|' \
	-e 's|^CA_ACCESS_TEAM_DOMAIN=.*|CA_ACCESS_TEAM_DOMAIN=guide.cloudflareaccess.com|' \
	-e 's|^CA_ACCESS_AUD=.*|CA_ACCESS_AUD=guide-aud|' -e 's|^CA_INITIAL_ADMIN_EMAIL=.*|CA_INITIAL_ADMIN_EMAIL=admin@example.com|' .env
mkdir -p secrets audit
openssl rand -hex 32 >secrets/kek
client_cert() { # 管理クライアントの証明書を作り、フィンガープリントを出す
	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$WORK/$1.key" -out "$WORK/$1.pem" -days 2 -subj "/CN=$1" 2>/dev/null
	openssl x509 -in "$WORK/$1.pem" -noout -fingerprint -sha256 | cut -d= -f2 | tr -d : | tr 'A-F' 'a-f'
}
FP_OLD=$(client_cert old)
FP_NEW=$(client_cert new)
echo "provisioner=$FP_OLD" >secrets/admin-clients
own secrets audit
docker network create "$PROVISIONER_SHARED_NETWORK" >/dev/null
docker compose build radsec-ca >/dev/null
docker compose up -d --wait radsec-ca
pass "起動"

docker compose exec -T radsec-ca /radsec-ca server-cert >"$WORK/server.pem" 2>/dev/null
chmod -R a+rX "$WORK"
# api <証明書> <メソッド> <パス> [本文のファイル]（共有のネットワークの中から、aka-provisioner の代わりに呼ぶ）
api() {
	local who=$1 method=$2 path=$3 body=${4:-}
	local args=(--silent --show-error --max-time 30 --cacert /w/server.pem --cert "/w/$who.pem" --key "/w/$who.key" -X "$method"
		-H "X-Operator-Id: guide" -H "Idempotency-Key: $(date +%s%N)" -w '\n%{http_code}')
	[ -n "$body" ] && args+=(-H 'Content-Type: application/json' --data-binary "@/w/$body")
	docker run --rm --network "$PROVISIONER_SHARED_NETWORK" -v "$WORK:/w:ro" "$CURL_IMAGE" "${args[@]}" "https://radsec-ca:9448$path"
}
code() { tail -n1 <<<"$1"; }
body() { sed '$d' <<<"$1"; }

r=$(api old GET /status) && [ "$(code "$r")" = 200 ] || fail "/status: $r"
body "$r" | grep -q '"service":"radsec-ca"' || fail "/status: $r"
pass "共有のネットワークから mTLS で /status"
if api new GET /status >/dev/null 2>&1; then fail "登録していない証明書が通った"; fi
pass "登録していない証明書は断る"

# 管理API と画面はホストに公開しない。配布の口だけを公開する。
docker compose port radsec-ca 8449 | grep -q '^127.0.0.1:' || fail "配布の口が公開されていない"
if docker compose port radsec-ca 9448 2>/dev/null | grep -q .; then fail "管理API が公開されている"; fi
if docker compose port radsec-ca 8448 2>/dev/null | grep -q .; then fail "画面が公開されている"; fi
PUBLISH=$(docker compose port radsec-ca 8449)
pass "配布の口だけを公開"

# 運用ガイド 3.2: ピンの入れ替え（ファイルをその場で書き換えて SIGHUP）。
printf 'provisioner=%s\nprovisioner=%s\n' "$FP_OLD" "$FP_NEW" | put secrets/admin-clients
docker compose kill -s SIGHUP radsec-ca >/dev/null
sleep 1
r=$(api new GET /status) && [ "$(code "$r")" = 200 ] || fail "新しい証明書: $r"
r=$(api old GET /status) && [ "$(code "$r")" = 200 ] || fail "入れ替えの間の古い証明書: $r"
echo "provisioner=$FP_NEW" | put secrets/admin-clients
docker compose kill -s SIGHUP radsec-ca >/dev/null
sleep 1
if api old GET /status >/dev/null 2>&1; then fail "古い証明書が残っている"; fi
docker compose logs --no-color radsec-ca | grep -q CA_ADMIN_CLIENTS_RELOADED || fail "読み直しのログがない"
pass "ピンの入れ替えと SIGHUP"

# 運用ガイド 3.3: サーバー証明書の作り直し。
docker compose exec -T radsec-ca /radsec-ca replace-server-cert >"$WORK/server-new.pem" 2>/dev/null
docker compose kill -s SIGHUP radsec-ca >/dev/null
sleep 1
cmp -s "$WORK/server.pem" "$WORK/server-new.pem" && fail "サーバー証明書が変わっていない"
if api new GET /status >/dev/null 2>&1; then fail "古いサーバー証明書で検証できた"; fi
cp "$WORK/server-new.pem" "$WORK/server.pem"
chmod -R a+rX "$WORK"
r=$(api new GET /status) && [ "$(code "$r")" = 200 ] || fail "新しいサーバー証明書: $r"
pass "サーバー証明書の作り直しと SIGHUP"

# 運用ガイド 4 章: 持ち込みの CA（アップロード）と配布。
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$WORK/v.key" -out "$WORK/v.pem" -days 30 -subj "/CN=vendor org CA" \
	-addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
mkdir -p "$WORK/crlca"
: >"$WORK/crlca/index.txt"
echo 01 >"$WORK/crlca/crlnumber"
cat >"$WORK/crlca/openssl.cnf" <<CNF
[ca]
default_ca = d
[d]
database = $WORK/crlca/index.txt
crlnumber = $WORK/crlca/crlnumber
default_md = sha256
default_crl_days = 7
CNF
openssl ca -config "$WORK/crlca/openssl.cnf" -gencrl -keyfile "$WORK/v.key" -cert "$WORK/v.pem" -out "$WORK/v.crl" 2>/dev/null
python3 - "$WORK" <<'PY'
import json, sys
w = sys.argv[1]
json.dump({"tenant": "tenant-a", "kind": "brought", "name": "vendor", "certPem": open(w + "/v.pem").read(), "tenantOnlyConfirmed": True,
           "crl": {"source": "upload", "pem": open(w + "/v.crl").read()}}, open(w + "/brought.json", "w"))
json.dump({"tenant": "tenant-a"}, open(w + "/tenant.json", "w"))
PY
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$WORK/g.key" -out "$WORK/g.csr" -subj "/CN=group" 2>/dev/null
python3 - "$WORK" <<'PY'
import json, sys
w = sys.argv[1]
json.dump({"profile": "group-client", "tenant": "tenant-a", "group": "unifi", "csr": open(w + "/g.csr").read()}, open(w + "/group.json", "w"))
PY
chmod -R a+rX "$WORK"
r=$(api new POST /cas brought.json) && [ "$(code "$r")" = 201 ] || fail "持ち込みの CA の登録: $r"
curl -sSf "http://$PUBLISH/crl/brought.tenant-a.vendor.pem" | openssl crl -noout -CAfile "$WORK/v.pem" 2>&1 | grep -q 'verify OK' || fail "配布の口の CRL"
pass "持ち込みの CA の登録と CRL の配布"
# 運用ガイド 4.1: 取得先に内部のアドレスは書けない（同じコンテナの配布の口を指しても断る）。
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$WORK/v2.key" -out "$WORK/v2.pem" -days 30 -subj "/CN=another CA" \
	-addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
python3 - "$WORK" <<'PY'
import json, sys
w = sys.argv[1]
json.dump({"tenant": "tenant-b", "kind": "brought", "name": "internal", "certPem": open(w + "/v2.pem").read(), "tenantOnlyConfirmed": True,
           "crl": {"source": "url", "url": "http://radsec-ca:8449/crl/server.pem"}}, open(w + "/internal.json", "w"))
PY
chmod a+r "$WORK/internal.json"
r=$(api new POST /cas internal.json) && [ "$(code "$r")" = 422 ] || fail "内部のアドレス: $r"
body "$r" | grep -q 'not a public address' || fail "内部のアドレスの文: $r"
pass "取得先の内部のアドレスを断る"
r=$(api new POST /cas tenant.json) && [ "$(code "$r")" = 201 ] || fail "テナントの CA: $r"
r=$(api new POST /certs group.json) && [ "$(code "$r")" = 201 ] || fail "グループの証明書: $r"
body "$r" | grep -q 'urn:example:grp:tenant-a:unifi' || fail "グループの証明書の SAN: $r"
pass "グループの証明書"

# 運用ガイド 5.2: 監査ログのファイル（UID 65532 が作るのでコンテナの中から読む）。
AUDIT=$(docker run --rm -v "$PWD/audit:/a:ro" busybox:1.37.0 sh -c 'cat /a/audit-*.jsonl')
for action in ca.register cert.issue server-cert.replace; do
	grep -q "\"action\":\"$action\"" <<<"$AUDIT" || fail "監査ログのファイルに $action がない: $AUDIT"
done
pass "監査ログのファイル"

# 運用ガイド 6 章: バックアップと戻し。
docker compose exec -T radsec-ca /radsec-ca backup -out /data/backup.db 2>/dev/null
r=$(api new POST /cas/brought.tenant-a.vendor/disable) && [ "$(code "$r")" = 200 ] || fail "停止: $r"
docker compose stop radsec-ca >/dev/null
docker run --rm -v "${COMPOSE_PROJECT_NAME}_ca-data:/data" busybox:1.37.0 sh -c \
	'mv /data/backup.db /data/radsec-ca.db && rm -f /data/radsec-ca.db-wal /data/radsec-ca.db-shm && chown 65532:65532 /data/radsec-ca.db'
docker compose up -d --wait radsec-ca
r=$(api new GET /cas/brought.tenant-a.vendor) && [ "$(code "$r")" = 200 ] || fail "戻した後: $r"
body "$r" | grep -q '"status":"active"' || fail "戻した後の状態: $r"
pass "バックアップと戻し"

# 運用ガイド 7 章: KEK の入れ替え。
docker compose stop radsec-ca >/dev/null
openssl rand -hex 32 | put secrets/kek-new
own secrets/kek-new
docker compose run --rm --no-deps -v "$PWD/secrets/kek-new:/run/secrets/kek-new:ro" radsec-ca rotate-kek -old /run/secrets/kek -new /run/secrets/kek-new >/dev/null 2>&1 || fail "rotate-kek"
if sudo -n true 2>/dev/null; then
	sudo mv secrets/kek secrets/kek-old
	sudo mv secrets/kek-new secrets/kek
else
	mv secrets/kek secrets/kek-old
	mv secrets/kek-new secrets/kek
fi
docker compose up -d --wait --force-recreate radsec-ca
r=$(api new GET /status) && [ "$(code "$r")" = 200 ] || fail "入れ替えた後: $r"
pass "KEK の入れ替え"

echo "すべて確かめました"
