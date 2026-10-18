-- 初版のスキーマ（設計概要 §8）。時刻はすべて UNIX 時間のミリ秒（UTC）。

-- 設定の値（KEK の識別子など）。
CREATE TABLE settings (
    name  TEXT PRIMARY KEY,
    value TEXT NOT NULL
) STRICT;

-- CA（§5.1）。id は server か tenant.<slug>。key_enc は PKCS#8 の DER を KEK で暗号化したもの（AES-256-GCM、AAD は id。§6.1）。
-- crl_number は最後に作った CRL の番号。
CREATE TABLE cas (
    id          TEXT    PRIMARY KEY,
    kind        TEXT    NOT NULL CHECK (kind IN ('server', 'tenant-client')),
    tenant      TEXT    NOT NULL DEFAULT '',
    cert_der    BLOB    NOT NULL,
    key_enc     BLOB    NOT NULL,
    key_nonce   BLOB    NOT NULL,
    kek_id      TEXT    NOT NULL,
    status      TEXT    NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    crl_number  INTEGER NOT NULL DEFAULT 0,
    not_after   INTEGER NOT NULL,
    created_at  INTEGER NOT NULL,
    disabled_at INTEGER NOT NULL DEFAULT 0,
    CHECK ((kind = 'server') = (tenant = ''))
) STRICT;

-- 発行した証明書（§8）。serial は 16 進（小文字、先頭の 0 なし）。記録は消さない。
CREATE TABLE certs (
    serial        TEXT    PRIMARY KEY,
    ca_id         TEXT    NOT NULL REFERENCES cas (id),
    profile       TEXT    NOT NULL CHECK (profile IN ('ap-client', 'probe-client', 'tenant-server')),
    tenant        TEXT    NOT NULL,
    ap            TEXT    NOT NULL DEFAULT '',
    edge          TEXT    NOT NULL DEFAULT '',
    cn            TEXT    NOT NULL,
    san_dns       TEXT    NOT NULL DEFAULT '',
    san_uri       TEXT    NOT NULL DEFAULT '',
    not_before    INTEGER NOT NULL,
    not_after     INTEGER NOT NULL,
    cert_der      BLOB    NOT NULL,
    pubkey_sha256 TEXT    NOT NULL,
    revoked_at    INTEGER NOT NULL DEFAULT 0,
    revoke_reason TEXT    NOT NULL DEFAULT '',
    issued_by     TEXT    NOT NULL DEFAULT '',
    trace_id      TEXT    NOT NULL DEFAULT '',
    created_at    INTEGER NOT NULL
) STRICT;
CREATE INDEX certs_tenant ON certs (tenant, profile, ap);
CREATE INDEX certs_not_after ON certs (not_after);
CREATE INDEX certs_ca_revoked ON certs (ca_id, revoked_at);

-- CRL（§7.2）。CA ごとに直近の 30 個を残す。
CREATE TABLE crls (
    ca_id       TEXT    NOT NULL REFERENCES cas (id),
    number      INTEGER NOT NULL,
    this_update INTEGER NOT NULL,
    next_update INTEGER NOT NULL,
    der         BLOB    NOT NULL,
    created_at  INTEGER NOT NULL,
    PRIMARY KEY (ca_id, number)
) STRICT;

-- 画面の利用者（§10.1）。
CREATE TABLE users (
    email      TEXT    PRIMARY KEY CHECK (email = lower(email) AND length(email) <= 64),
    role       TEXT    NOT NULL CHECK (role IN ('admin', 'viewer')),
    enabled    INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
) STRICT;

-- 監査ログ（§13）。details は JSON。鍵・KEK・CSR と証明書の本体は入れない。
CREATE TABLE audit (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    time        INTEGER NOT NULL,
    operator    TEXT    NOT NULL DEFAULT '',
    mgmt_client TEXT    NOT NULL DEFAULT '',
    source      TEXT    NOT NULL CHECK (source IN ('api', 'gui', 'cli', 'system')),
    action      TEXT    NOT NULL,
    target      TEXT    NOT NULL DEFAULT '',
    trace_id    TEXT    NOT NULL DEFAULT '',
    result      TEXT    NOT NULL DEFAULT 'ok',
    details     TEXT    NOT NULL DEFAULT '{}'
) STRICT;

-- 冪等の記録（§9.2）。同じ管理クライアント・同じ鍵の再送には、覚えた応答を返す。
CREATE TABLE idempotency (
    mgmt_client  TEXT    NOT NULL,
    key          TEXT    NOT NULL,
    req_hash     TEXT    NOT NULL,
    status       TEXT    NOT NULL CHECK (status IN ('pending', 'done')),
    resp_status  INTEGER NOT NULL DEFAULT 0,
    resp_type    TEXT    NOT NULL DEFAULT '',
    response     BLOB    NOT NULL DEFAULT x'',
    created_at   INTEGER NOT NULL,
    expires_at   INTEGER NOT NULL,
    PRIMARY KEY (mgmt_client, key)
) STRICT;
CREATE INDEX idempotency_expires ON idempotency (expires_at);
