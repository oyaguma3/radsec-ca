# radsec-ca 運用ガイド

- 状態: 2026-10-31。単独モードの手順は radsec-edge の `scripts/e2e.sh`（simwifi）で確かめた。管理モードの手順は `scripts/check-guide.sh`（CI のジョブ「運用ガイドの手順の通し確認」）で確かめる。aka-provisioner・エッジとつないだ通しと、Cloudflare を通す部分は MVP セットの段階 4 の通し（aka-mvpset の `verify/stage4/`）で確かめる。
- 対象: 本CA を導入・運用する人（CA の担当者）。証明書と CA の考え方は[設計概要 §1・§5・§7](design-overview.md)にある。

## 1. 構成

| 部品 | 内容 |
|---|---|
| `radsec-ca` | 本CA（画面 8448、管理API 9448、配布 8449）。DB（SQLite）と管理API のサーバー証明書は名前つきボリューム `ca-data`、KEK は `secrets/kek` |
| `cloudflared` | Cloudflare Tunnel のコネクター（画面だけを Cloudflare Access の後ろに出す） |

- 使い方は 2 つある。**単独モード**は radsec-edge の画面と組み合わせ、管理API を使わない（`compose.yaml` だけ。3.5）。**管理モード**は MVP セットの管理面のノードで aka-provisioner から使う（`compose.managed.yaml` を重ねる。3 章）。
- 配布の口はトンネル（WireGuard など）のアドレス（`CA_BIND_ADDR`）だけで公開する。管理モードの管理API はホストに公開せず、共有の Docker のネットワークで受ける。画面は公開しない。
- コンテナは distroless の nonroot（UID 65532）で動く。シェルはないので、コマンドは `docker compose exec -T radsec-ca /radsec-ca <コマンド>` か `docker compose run --rm radsec-ca <コマンド>` で動かす。

## 2. 導入

### 2.1 KEK

KEK（CA の鍵と Meraki の API キーを暗号化する鍵）は 32 バイトの乱数を 16 進で書いたファイルで、DB とは別に保管する。**KEK を失うと、すべての CA を作り直し、すべての証明書を出し直すことになる。**

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
- `CA_BIND_ADDR`: トンネルの、このホストのアドレス。起動の前に、そのアドレスがホストのインターフェースにあること（WireGuard を先に上げる）。ないと、ポートを公開できずにコンテナが起動しない。
- `CA_ACCESS_TEAM_DOMAIN`・`CA_ACCESS_AUD`・`CA_INITIAL_ADMIN_EMAIL`: 画面の認証。最初の管理者は、起動のたびに admin・有効に戻る。

Cloudflare Tunnel のトークンは `secrets/tunnel-token` に置き、`sudo chown 65532 secrets/tunnel-token && sudo chmod 600 secrets/tunnel-token` にする。Tunnel の公開ホスト名の向け先は `http://radsec-ca:8448`。

### 2.3 起動

```bash
docker compose build
docker compose up -d
docker compose logs radsec-ca
```

初めての起動で DB とサーバーCA（ID `server`）と、そのサーバーCA の最初の CRL を作る。ログの `kek_id` が KEK の識別子。

管理モードでは、先に 3.1 の準備をする。

## 3. 管理モード（aka-provisioner から使う）

### 3.1 導入

aka-provisioner の compose を先に起動する（共有のネットワーク `aka-provisioner` を作るため）。

1. `.env` に `COMPOSE_FILE=compose.yaml:compose.managed.yaml` を書く。ログを管理面の Fluent Bit に送るときは `COMPOSE_FILE=compose.yaml:compose.managed.yaml:compose.fluent-bit.yaml`。
2. `CA_TLS_HOSTS` は管理API のサーバー証明書の SAN。既定の `radsec-ca` のままなら、aka-provisioner からは `https://radsec-ca:9448` でつなぐ。
3. aka-provisioner のクライアント証明書のフィンガープリントを、ピンのファイルに書く。1 行に `識別名=フィンガープリント`。`#` で始まる行は無視する。

   ```bash
   mkdir -p audit
   echo "aka-provisioner=<SHA-256 のフィンガープリント>" > secrets/admin-clients
   sudo chown 65532 secrets/admin-clients audit && sudo chmod 600 secrets/admin-clients
   ```

4. `docker compose up -d` で起動する。ピンのファイルがあって読めない・1 つもないときは起動しない。`audit/` に UID 65532 で書けないときは `CA_AUDIT_DIR_ERR` を出して起動しない。

サーバー証明書は自己署名で、初めての起動で作る。aka-provisioner の登録簿には、この証明書を渡す（aka-provisioner の運用ガイド）。

```bash
docker compose exec -T radsec-ca /radsec-ca server-cert > radsec-ca-server.pem
```

標準エラーにフィンガープリントが出る。

### 3.2 ピンの入れ替え（aka-provisioner のクライアント証明書を替えるとき）

再起動は要らない。

1. ピンのファイルに新しい行を足す（同じ識別名に新旧の 2 行）。
2. `docker compose kill -s SIGHUP radsec-ca` で読み直す。ログに `CA_ADMIN_CLIENTS_RELOADED` が出る。読めないときは `CA_ADMIN_CLIENTS_RELOAD_ERR` を出して前の設定のまま続く。
3. aka-provisioner を新しい証明書に切り替える。
4. 古い行を消して、もう一度 `SIGHUP` を送る。

**ファイルはその場で書き換える。** `sed -i` や `mv` で置き換えると、動いているコンテナは単一ファイルのマウントで古い中身を読み続ける（`SIGHUP` を送っても変わらない）。置き換えたら `docker compose up -d --force-recreate radsec-ca` で作り直す。

### 3.3 サーバー証明書の入れ替え

有効期限は 10 年。期限の前のほか、`CA_TLS_HOSTS` を変えるときにも行う。

```bash
docker compose exec -T radsec-ca /radsec-ca replace-server-cert > radsec-ca-server.pem
docker compose kill -s SIGHUP radsec-ca
```

`SIGHUP` の後は新しい証明書を使うので、すぐに aka-provisioner の登録簿の証明書を替えて読み直す（aka-provisioner の運用ガイド。替えるまでの間、aka-provisioner からの呼び出しは失敗する）。ログに `CA_SERVER_CERT_RELOADED` が出る。

### 3.4 操作の入口

管理モードでは、CA の作成、発行、持ち込みの CA の登録は aka-ossbss の画面から aka-provisioner を通して行う。本CA の画面で操作すると aka-ossbss の台帳とずれるので、緊急の失効と停止のほかは使わない（使ったら aka-ossbss の側でも処理する）。

### 3.5 単独モードの流れ（radsec-edge の画面と組み合わせる）

1. 本CA の画面のダッシュボードで、テナントのクライアントCA を作る（テナントの名前はエッジと同じ）。
2. CA の詳細から CA の証明書を取り出し、エッジの画面（テナントの「クライアントCA」）に取り込む。エッジは CRL を配布の口（`EDGE_CRL_BASE_URL` に `http://<CA_BIND_ADDR>:8449` を書く）から取る。
3. エッジの画面で出したサーバー証明書の CSR を、本CA の「署名」で `tenant-server`（テナントとエッジの名前）として署名し、エッジに取り込む。ヘルスチェック用の CSR も `probe-client` で同じようにする。
4. AP の CSR を `ap-client`（テナントと AP の名前）で署名し、AP に入れる。エッジの画面で同じ名前の AP を登録する。AP にはサーバーCA の証明書（CA `server` の証明書）も入れる。
5. 失効は証明書の詳細で行う。エッジは 5 分ごとに CRL を取りに来るので、エッジの側の操作は要らない（すぐ効かせたいときは、エッジの画面で「今すぐ取りに行く」）。

radsec-edge の `scripts/e2e.sh` は、本CA を compose で導入し、管理API でテナントのクライアントCA の作成・署名・失効を行って、エッジが配布の口から CA の証明書と CRL を取ることまで確かめる（radsec-edge の運用ガイド 8 章）。画面の操作の代わりに管理API を使うが、署名と失効の中身は画面と同じ（どちらも ca の同じ処理を呼ぶ）。

## 4. 持ち込みの CA

業者の CA が AP に証明書を発行する製品（Meraki、Mist など）のために、テナント専用の業者の CA を登録する（設計概要 §19.2）。登録と取得先の変更は aka-ossbss の画面（システム管理者）から行う。本CA の画面では、状態を見る、CRL を取り直す・置く、停止する。

### 4.1 CRL の取得先

| 取得先 | 運用 | 外への通信 |
|---|---|---|
| `url` | 1 時間ごとに自動で取る | 管理面のノードから業者の CRL の URL へ（ファイアウォールで許す） |
| `meraki` | 1 時間ごとに自動で取る。顧客の読み取り専用の管理者の API キーを預かる（KEK で暗号化して持つ）。**キーは CRL 以外の情報も読めるので、預ける先を顧客と取り決める。** 預けたくない顧客には `upload` を使う | 管理面のノードから `api.meraki.com` へ |
| `upload` | **人が期限の前に新しい CRL を置く。** 置き忘れると、その CA の AP の新しい接続が拒否される | なし |
| `none` | CRL がない。業者の AP の失効が効かない。さらにテナント全体が `CRLCheck off` になり、こちらが発行した証明書も CRL では止まらなくなる（失効はエッジのブロックを消して行う） | なし |

- URL は公開のアドレスに限る。内部のアドレス（ループバック、プライベート、`100.64.0.0/10` など）は断る。そうでない置き場の CRL は `upload` で受ける。
- 登録と取得先の変更は、その場で CRL が取れたときだけ成功する。業者のサーバーが一時的に止まっていれば、後でやり直す。

### 4.2 CRL の警告

ダッシュボードと CA の詳細（管理API の `crlWarning`）に出る。

| 警告 | 対応 |
|---|---|
| 3 回続けて更新に失敗 | CA の詳細の「更新に失敗」の文を見る。URL やキーが変わっていれば aka-ossbss から取得先を変える。業者の側の障害なら回復を待つ（今の CRL は残る） |
| nextUpdate が近づいている | 閾値は 3 日（CRL の有効期間が 6 日より短いときは、その半分）。`upload` なら新しい CRL を置く。ほかは上と同じ |
| nextUpdate を過ぎた | その CA の AP の新しい接続が拒否されている。急いで CRL を置くか、取得を直す |

**業者の CRL の猶予は、本CA の CRL の 7 日とは違い、業者の `nextUpdate` 次第である。** 有効期間の短い業者の CRL では、本CA が止まっている間に早く期限が切れる。

### 4.3 CRL のアップロード

CA の詳細の「CRL を置く」で、PEM を貼り付けるか PEM・DER のファイルを選ぶ（1 MiB まで）。署名、発行者、期限、番号の後退を確かめ、通らなければ今の CRL を残す。

### 4.4 業者の CA の侵害・失効を知ったとき

本CA は業者の上位の CA の CRL を取らないので、業者の CA そのものの失効には気づけない。知ったら次の順で行う。**順番を逆にしない。**

1. aka-ossbss でその持ち込みの CA をテナントから外し、そのテナントを置いたすべてのエッジに反映する。
2. 外し終わってから、本CA でその持ち込みの CA を停止する。CRL の取得を止め、API キーを消す。

停止した CA を登録し直せるのは、同じ CA を別の名前で登録するときだけで、侵害された CA を登録し直さないことは運用で守る。

## 5. 監視とログ

### 5.1 ダッシュボード

- 画面のダッシュボード（または管理API の `GET /status`）で、CA ごとの CRL の番号と nextUpdate、作り直しの失敗を見る。本CA の CRL は 1 日ごとに作り直し、nextUpdate は 7 日後。**本CA が止まっている時間が 6 日を超えると、エッジは警告（残り 3 日）を出し始める。7 日を超えると、エッジは新しい接続を受けられなくなる。**
- 期限の近い証明書（30 日以内）は、ダッシュボードの数と証明書の一覧（「30 日以内に期限が切れるもの」）で見る。

### 5.2 ログと監査ログ

- アプリケーションログは JSON で、`event_id` で絞り込める。

| `event_id` | 意味・対応 |
|---|---|
| `CA_STARTED` | 起動した |
| `CA_CERT_ISSUED`・`CA_CERT_REVOKED` | 発行した・失効させた |
| `CA_CRL_PUBLISHED` | 本CA の CRL を作った |
| `CA_CRL_FAILED` | 本CA の CRL を作れない。放置するとエッジの CRL の期限が切れる。ログの `error` を見る |
| `CA_BROUGHT_CRL_UPDATED` | 持ち込みの CA の新しい CRL を置いた |
| `CA_BROUGHT_CRL_FAILED` | 持ち込みの CA の CRL を取れない・置けない（4.2） |
| `CA_KEK_MISMATCH` | KEK が DB と合わないので起動しない。正しい KEK を置く（6.2、7 章） |
| `CA_AUTH_REJECTED` | 登録していない管理クライアントの接続を断った。ログの `fingerprint` で確かめる |
| `CA_ADMIN_CLIENTS_RELOADED`・`CA_ADMIN_CLIENTS_RELOAD_ERR` | ピンを読み直した・読み直せず前のまま（3.2） |
| `CA_SERVER_CERT_RELOADED`・`CA_SERVER_CERT_RELOAD_ERR` | サーバー証明書を読み直した・読み直せず前のまま（3.3） |
| `CA_AUDIT_DIR_ERR`・`CA_AUDIT_WRITE_ERR`・`CA_AUDIT_FILE_ERR` | 監査ログのディレクトリに書けない・書き込みか整理に失敗した。持ち主と権限、空きを確かめる |

- 管理モードでは、`compose.fluent-bit.yaml` を重ねて管理面の Fluent Bit に送る（`radsec-ca.log`・`radsec-ca-cloudflared.log`。日ごとに圧縮して 2 週間持つ）。監視用の PC が取りに行く。
- 監査ログは DB の `audit`（画面の「監査ログ」）と、日ごとのファイル `audit/audit-YYYYMMDD.jsonl`（日本時間。前の日までは gzip。`CA_AUDIT_RETENTION_DAYS`、既定 14 日で消す）に書く。残すのは、CA の作成・登録・停止、CRL の取得先の変更・取り直し・アップロード、発行、失効、利用者の変更、KEK の入れ替え、バックアップ、サーバー証明書の作り直し。鍵、KEK、API キー、CSR と証明書の本体は残さない。

## 6. バックアップと戻し方

### 6.1 バックアップ

動かしたまま DB の写しを作れる（SQLite の `VACUUM INTO`）。写しには暗号化した CA の鍵と API キーが入るので、KEK とは別の場所に置く。

```bash
docker compose exec -T radsec-ca /radsec-ca backup -out /data/backup-$(date +%Y%m%d).db
docker cp radsec-ca-radsec-ca-1:/data/backup-$(date +%Y%m%d).db ./backups/
docker compose exec -T radsec-ca /radsec-ca backup -h   # 使い方
```

コンテナの中の写しは、取り出したら消す（ボリュームの空きを使うため）。

### 6.2 戻し方

1. `docker compose stop radsec-ca` で止める。
2. 写しをボリュームの `/data/radsec-ca.db` に置き、`radsec-ca.db-wal` と `radsec-ca.db-shm` があれば消す（例: `docker run --rm -v radsec-ca_ca-data:/data -v ./backups:/b busybox:1.37.0 sh -c 'cp /b/<写し> /data/radsec-ca.db && rm -f /data/radsec-ca.db-wal /data/radsec-ca.db-shm && chown 65532:65532 /data/radsec-ca.db'`）。
3. 写しを作ったときの KEK が `secrets/kek` にあることを確かめて、`docker compose start radsec-ca` で起動する。KEK が違えば `CA_KEK_MISMATCH` で起動しない。`secrets/kek` を別のファイルに置き換えたときは、`start` ではなく `docker compose up -d --force-recreate radsec-ca` で作り直す（7 章の手順 4 と同じ理由）。
4. **写しの後に発行・失効した証明書の記録はなくなる。** 失効させた証明書があれば、もう一度失効させる（失効が消えたまま動かさない）。写しの後の持ち込みの CA の登録・停止・取得先の変更もなくなるので、aka-ossbss の台帳と照らし合わせて行い直す。持ち込みの CA の CRL は次の取得で新しくなる（`upload` は置き直す）。

## 7. KEK の入れ替え

1. 新しい KEK を作る（2.1 と同じ。例 `secrets/kek-new`）。
2. `docker compose stop radsec-ca` で止める。
3. 新しい KEK をマウントして入れ替える。CA の鍵と Meraki の API キーを暗号化し直す。

   ```bash
   docker compose run --rm -v ./secrets/kek-new:/run/secrets/kek-new:ro radsec-ca rotate-kek -old /run/secrets/kek -new /run/secrets/kek-new
   ```

4. `secrets/kek` を新しいファイルに置き換え（古い KEK は、入れ替える前に取ったバックアップのために保管しておく）、コンテナを作り直して起動する。

   ```bash
   mv secrets/kek secrets/kek-old && mv secrets/kek-new secrets/kek
   docker compose up -d --force-recreate radsec-ca
   ```

   `docker compose start radsec-ca` では起動しない。KEK のファイルは単一ファイルの bind mount で、コンテナは作ったときのファイル（inode）を指し続けるため、`mv` で置き換えても古い KEK を読み、`CA_KEK_MISMATCH` で止まる（2026-10-28 に手元の compose で確かめた）。`docker compose up -d --force-recreate radsec-ca` で作り直すと、新しいファイルを読む。

## 8. 更新

段階 2 の版からの更新では、起動のときにスキーマを移行する（`0002`）。先にバックアップを取る（6.1）。環境変数 `CA_ADMIN_CLIENTS` は使えなくなったので、ピンのファイルに移す（3.1。コンテナに渡していると起動しない）。

## 9. 片付け

```bash
docker compose down        # ボリューム（DB）は残る
docker compose down -v     # DB も消す（CA の鍵も消える。戻せない）
```
