# radsec-ca 運用ガイド（下書き）

- 状態: 下書き（2026-10-18）。段階 3（radsec-edge とつないだ単独モードの通し。simwifi）で手直しする（設計概要 §18 の 1）。
- 対象: 本CA を導入・運用する人（CA の担当者）。

## 1. 構成

| 部品 | 内容 |
|---|---|
| `radsec-ca` | 本CA（画面 8448、管理API 9448、配布 8449）。DB（SQLite）と管理API のサーバー証明書は名前つきボリューム `ca-data`、KEK は `secrets/kek` |
| `cloudflared` | Cloudflare Tunnel のコネクター（画面だけを Cloudflare Access の後ろに出す） |

- 管理API と配布の口は、トンネル（WireGuard など）のアドレス（`CA_BIND_ADDR`）だけで公開する。画面は公開しない。
- コンテナは distroless の nonroot（UID 65532）で動く。シェルはないので、コマンドは `docker compose exec -T radsec-ca /radsec-ca <コマンド>` か `docker compose run --rm radsec-ca <コマンド>` で動かす。

## 2. 導入

### 2.1 KEK

KEK（CA の鍵を暗号化する鍵）は 32 バイトの乱数を 16 進で書いたファイルで、DB とは別に保管する。**KEK を失うと、すべての CA を作り直し、すべての証明書を出し直すことになる。**

```bash
mkdir -p secrets && chmod 700 secrets
openssl rand -hex 32 > secrets/kek
sudo chown 65532 secrets/kek && sudo chmod 600 secrets/kek
```

（`radsec-ca gen-kek -out <ファイル>` でも作れる。）作ったら、オフラインの保管場所にも写しを置く。

### 2.2 設定

`cp .env.example .env` して書き換え、`chmod 600 .env` にする。

- `CA_ORG`: CA の Subject の O と CN に入る組織の名前（作った CA の名前は後から変わらない）。
- `CA_URN_PREFIX`・`CA_DNS_DOMAIN`: エッジの `EDGE_URN_PREFIX`・`EDGE_DNS_DOMAIN` と同じ値にそろえる。
- `CA_BIND_ADDR`: トンネルの、このホストのアドレス。
- `CA_ACCESS_TEAM_DOMAIN`・`CA_ACCESS_AUD`・`CA_INITIAL_ADMIN_EMAIL`: 画面の認証。最初の管理者は、起動のたびに admin・有効に戻る。
- 管理モード（provisioner から使う）では、`CA_ADMIN_CLIENTS`（provisioner のクライアント証明書の `識別名=フィンガープリント`）と `CA_TLS_HOSTS`（provisioner からつなぐ名前やアドレス）も書く。単独モードでは空のままにする（管理API を待ち受けない）。

Cloudflare Tunnel のトークンは `secrets/tunnel-token` に置き、`sudo chown 65532 secrets/tunnel-token && sudo chmod 600 secrets/tunnel-token` にする。Tunnel の公開ホスト名の向け先は `http://radsec-ca:8448`。

### 2.3 起動

```bash
docker compose build
docker compose up -d
docker compose logs radsec-ca
```

初めての起動で DB とサーバーCA（ID `server`）と、そのサーバーCA の最初の CRL を作る。ログの `kek_id` が KEK の識別子。

### 2.4 管理API のサーバー証明書（管理モード）

管理API のサーバー証明書は自己署名で、初めての起動で作る（SAN は `CA_TLS_HOSTS`）。provisioner には、この証明書を検証用として渡す。

```bash
docker compose exec -T radsec-ca /radsec-ca server-cert > radsec-ca-server.pem
```

標準エラーにフィンガープリントが出る。

## 3. 単独モードの流れ（radsec-edge の画面と組み合わせる）

1. 本CA の画面のダッシュボードで、テナントのクライアントCA を作る（テナントの名前はエッジと同じ）。
2. CA の詳細から CA の証明書を取り出し、エッジの画面（テナントの「クライアントCA」）に取り込む。エッジは CRL を配布の口（`EDGE_CRL_BASE_URL` に `http://<CA_BIND_ADDR>:8449` を書く）から取る。
3. エッジの画面で出したサーバー証明書の CSR を、本CA の「署名」で `tenant-server`（テナントとエッジの名前）として署名し、エッジに取り込む。ヘルスチェック用の CSR も `probe-client` で同じようにする。
4. AP の CSR を `ap-client`（テナントと AP の名前）で署名し、AP に入れる。エッジの画面で同じ名前の AP を登録する。AP にはサーバーCA の証明書（CA `server` の証明書）も入れる。
5. 失効は証明書の詳細で行う。エッジは 5 分ごとに CRL を取りに来るので、エッジの側の操作は要らない（すぐ効かせたいときは、エッジの画面で「今すぐ取りに行く」）。

## 4. 監視

- 画面のダッシュボード（または管理API の `GET /status`）で、CA ごとの CRL の番号と nextUpdate、作り直しの失敗を見る。CRL は 1 日ごとに作り直し、nextUpdate は 7 日後。**本CA が止まっている時間が 6 日を超えると、エッジは警告（残り 3 日）を出し始める。7 日を超えると、エッジは新しい接続を受けられなくなる。**
- 期限の近い証明書（30 日以内）は、ダッシュボードの数と証明書の一覧（「30 日以内に期限が切れるもの」）で見る。
- ログは JSON で、`event_id`（`CA_STARTED`、`CA_CERT_ISSUED`、`CA_CERT_REVOKED`、`CA_CRL_PUBLISHED`、`CA_CRL_FAILED`、`CA_KEK_MISMATCH`、`CA_AUTH_REJECTED`）で絞り込める。

## 5. バックアップと戻し方

### 5.1 バックアップ

動かしたまま DB の写しを作れる（SQLite の `VACUUM INTO`）。写しには暗号化した CA の鍵が入るので、KEK とは別の場所に置く。

```bash
docker compose exec -T radsec-ca /radsec-ca backup -out /data/backup-$(date +%Y%m%d).db
docker cp radsec-ca-radsec-ca-1:/data/backup-$(date +%Y%m%d).db ./backups/
docker compose exec -T radsec-ca /radsec-ca backup -h   # 使い方
```

コンテナの中の写しは、取り出したら消す（ボリュームの空きを使うため）。

### 5.2 戻し方

1. `docker compose stop radsec-ca` で止める。
2. 写しをボリュームの `/data/radsec-ca.db` に置き、`radsec-ca.db-wal` と `radsec-ca.db-shm` があれば消す（例: `docker run --rm -v radsec-ca_ca-data:/data -v ./backups:/b busybox:1.37.0 sh -c 'cp /b/<写し> /data/radsec-ca.db && rm -f /data/radsec-ca.db-wal /data/radsec-ca.db-shm && chown 65532:65532 /data/radsec-ca.db'`）。
3. 写しを作ったときの KEK が `secrets/kek` にあることを確かめて、`docker compose start radsec-ca` で起動する。KEK が違えば `CA_KEK_MISMATCH` で起動しない。
4. 写しの後に発行・失効した証明書の記録はなくなる。失効させた証明書があれば、もう一度失効させる。

## 6. KEK の入れ替え

1. 新しい KEK を作る（2.1 と同じ。例 `secrets/kek-new`）。
2. `docker compose stop radsec-ca` で止める。
3. 新しい KEK をマウントして入れ替える。

   ```bash
   docker compose run --rm -v ./secrets/kek-new:/run/secrets/kek-new:ro radsec-ca rotate-kek -old /run/secrets/kek -new /run/secrets/kek-new
   ```

4. `secrets/kek` を新しいファイルに置き換え（古い KEK は、入れ替える前に取ったバックアップのために保管しておく）、`docker compose start radsec-ca` で起動する。

## 7. 片付け

```bash
docker compose down        # ボリューム（DB）は残る
docker compose down -v     # DB も消す（CA の鍵も消える。戻せない）
```
