-- 持ち込みの CA とグループの証明書（設計概要 §19）。
-- SQLite は CHECK を変えられないので、cas・certs・crls を作り直す。外部キーを有効にしたまま作り直せるよう、
-- 子の表（certs・crls）を制約のない写しに移して消してから、親（cas）を作り直す。

CREATE TABLE certs_copy AS SELECT rowid AS rid, * FROM certs;
CREATE TABLE crls_copy AS SELECT * FROM crls;
DROP TABLE certs;
DROP TABLE crls;

-- CA（§5.1、§19.5）。
-- kind が tenant-brought の CA は証明書だけを持ち、key_enc・key_nonce は空（本CA は署名しない）。
-- crl_number は crls.number の最後の値（持ち込みの CA では、CRL を置くたびに増やすこちらの連番）。
-- crl_source は issued（本CA が作る）か、持ち込みの CA の取得先（url / meraki / upload / none）。
-- meraki_key_enc は Meraki の API キーを KEK で暗号化したもの（AAD は <id>/meraki-key。§19.3）。
CREATE TABLE cas_new (
    id               TEXT    PRIMARY KEY,
    kind             TEXT    NOT NULL CHECK (kind IN ('server', 'tenant-client', 'tenant-brought')),
    tenant           TEXT    NOT NULL DEFAULT '',
    cert_der         BLOB    NOT NULL,
    key_enc          BLOB    NOT NULL,
    key_nonce        BLOB    NOT NULL,
    kek_id           TEXT    NOT NULL,
    status           TEXT    NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    crl_number       INTEGER NOT NULL DEFAULT 0,
    not_after        INTEGER NOT NULL,
    created_at       INTEGER NOT NULL,
    disabled_at      INTEGER NOT NULL DEFAULT 0,
    self_signed      INTEGER NOT NULL DEFAULT 1 CHECK (self_signed IN (0, 1)),
    fingerprint      TEXT    NOT NULL DEFAULT '',
    crl_source       TEXT    NOT NULL DEFAULT 'issued' CHECK (crl_source IN ('issued', 'url', 'meraki', 'upload', 'none')),
    crl_url          TEXT    NOT NULL DEFAULT '',
    meraki_org_id    TEXT    NOT NULL DEFAULT '',
    meraki_key_enc   BLOB    NOT NULL DEFAULT x'',
    meraki_key_nonce BLOB    NOT NULL DEFAULT x'',
    crl_etag         TEXT    NOT NULL DEFAULT '',
    crl_modified     TEXT    NOT NULL DEFAULT '',
    crl_checked_at   INTEGER NOT NULL DEFAULT 0,
    crl_ok_at        INTEGER NOT NULL DEFAULT 0,
    crl_failures     INTEGER NOT NULL DEFAULT 0,
    crl_last_error   TEXT    NOT NULL DEFAULT '',
    tenant_only_by   TEXT    NOT NULL DEFAULT '',
    tenant_only_at   INTEGER NOT NULL DEFAULT 0,
    no_crl_by        TEXT    NOT NULL DEFAULT '',
    no_crl_at        INTEGER NOT NULL DEFAULT 0,
    CHECK ((kind = 'server') = (tenant = '')),
    CHECK ((kind = 'tenant-brought') = (crl_source != 'issued'))
) STRICT;
INSERT INTO cas_new (id, kind, tenant, cert_der, key_enc, key_nonce, kek_id, status, crl_number, not_after, created_at, disabled_at)
    SELECT id, kind, tenant, cert_der, key_enc, key_nonce, kek_id, status, crl_number, not_after, created_at, disabled_at FROM cas;
DROP TABLE cas;
ALTER TABLE cas_new RENAME TO cas;
-- 有効な持ち込みの CA の中で、同じ CA（証明書の SHA-256）を重ねない（§19.2）。止めた CA は数えない。
CREATE UNIQUE INDEX cas_brought_fingerprint ON cas (fingerprint) WHERE kind = 'tenant-brought' AND status = 'active';

-- 発行した証明書。grp はグループの名前（profile が group-client のとき）。
CREATE TABLE certs (
    serial        TEXT    PRIMARY KEY,
    ca_id         TEXT    NOT NULL REFERENCES cas (id),
    profile       TEXT    NOT NULL CHECK (profile IN ('ap-client', 'probe-client', 'tenant-server', 'group-client')),
    tenant        TEXT    NOT NULL,
    ap            TEXT    NOT NULL DEFAULT '',
    edge          TEXT    NOT NULL DEFAULT '',
    grp           TEXT    NOT NULL DEFAULT '',
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
-- 一覧の順（発行した順）を保つため、rowid も写す。
INSERT INTO certs (rowid, serial, ca_id, profile, tenant, ap, edge, cn, san_dns, san_uri, not_before, not_after, cert_der, pubkey_sha256,
        revoked_at, revoke_reason, issued_by, trace_id, created_at)
    SELECT rid, serial, ca_id, profile, tenant, ap, edge, cn, san_dns, san_uri, not_before, not_after, cert_der, pubkey_sha256,
        revoked_at, revoke_reason, issued_by, trace_id, created_at FROM certs_copy;
CREATE INDEX certs_tenant ON certs (tenant, profile, ap);
CREATE INDEX certs_not_after ON certs (not_after);
CREATE INDEX certs_ca_revoked ON certs (ca_id, revoked_at);

-- CRL（§7.2）。number は CA ごとのこちらの連番。ext_number は持ち込みの CRL の cRLNumber の 10 進の文字列
-- （最大 20 バイトで整数の列に入らず、ないこともある。§19.3）。
CREATE TABLE crls (
    ca_id       TEXT    NOT NULL REFERENCES cas (id),
    number      INTEGER NOT NULL,
    this_update INTEGER NOT NULL,
    next_update INTEGER NOT NULL,
    der         BLOB    NOT NULL,
    created_at  INTEGER NOT NULL,
    ext_number  TEXT    NOT NULL DEFAULT '',
    PRIMARY KEY (ca_id, number)
) STRICT;
INSERT INTO crls (ca_id, number, this_update, next_update, der, created_at)
    SELECT ca_id, number, this_update, next_update, der, created_at FROM crls_copy;

DROP TABLE certs_copy;
DROP TABLE crls_copy;
