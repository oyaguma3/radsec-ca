# radsec-ca 設計概要

- 状態: 下書き（2026-10-18）。radsec-edge の設計概要（以下「エッジの設計概要」）の決定事項と §9（証明書と CA）をもとに、CA の詳しい作りを書いた。§17 の確認事項は 2026-10-18 にすべて推奨案で合意し（§3 の 6）、§16 のとおりエッジの設計概要に反映した。実装（エッジの段階 2）に入る前の確認事項（§18）も 2026-10-18 にすべて推奨案で合意した（§3 の 7）。2026-10-20 に、MVP セット（aka-mvpset）のための変更（持ち込みの CA と Box。§19）を加え（§3 の 8）、2026-10-21 に業者の製品の調べとラボの結果で改めた（§3 の 9）。
- 対象: RadSec のエッジのための独立CA（コマンド名 `radsec-ca`。以下「本CA」）。
- 関連:
  - radsec-edge: `docs/design-overview.md`（全体の構成、名前の規則 §8、証明書と CA §9、CA の API の概要 §12.2、主な流れ §14、段階 0 の実機の検証 §18）
  - eapaka-node-provisioner（以下「provisioner」）: `docs/design-overview.md`（管理クライアントの認証 §10.1、操作者・トレースID・監査ログ §10.2）
  - eapaka-ossbss-sample（以下「OSS/BSS」）: `docs/design-overview.md`（Cloudflare Access の JWT の検証 §5、画面の作り §4）
- 手本にする実装: OSS/BSS（画面、Cloudflare Access、スキーマの移行）、provisioner（mTLS とフィンガープリント、ProblemDetails、監査ログ）、radsec-edge の `verify/v0/tools/cmd/certgen`（`crypto/x509` による CA・証明書・CRL の作成。段階 0 で radsecproxy が受け付けることを確かめた）

## 1. 位置づけ

AP のクライアント証明書と、エッジのサーバー証明書を発行する CA。エッジの外の中央に 1 つ置く（エッジの設計概要 決定事項 6）。

```
 [運用者のブラウザ] ─Cloudflare Access─> cloudflared ─HTTP─> 本CA の画面（8448）
 [provisioner] ──────mTLS（トンネルの中）──────────────────> 本CA の API（9448）     ── SQLite（CA の鍵は暗号化）
 [エッジ 1..n] ──────HTTP（トンネルの中）──────────────────> 本CA の配布（8449）      ── KEK（ファイル）
                       CA の証明書と CRL（公開してよい情報）
```

- 本CA が持つのは、CA（鍵と証明書）、発行した証明書の記録、CRL、画面の利用者、監査ログだけである。テナント・AP・エッジの台帳は持たない（管理モードでは OSS/BSS、単独モードではエッジにある）。
- 証明書の中身（CN、SAN、EKU、有効期限）は、呼び出し側が渡す名前（テナント、AP、エッジ）から、本CA が決まった規則（プロファイル。§5）で作る。呼び出し側は SAN の文字列そのものを渡せない。
- API の呼び出し側は provisioner だけで、provisioner を全権として扱う（PoC セットの他の下流と同じ。誰がどのテナントを操作してよいかは OSS/BSS が決める）。
- エッジは本CA の API を呼ばない。CA の証明書と CRL を、配布の口（8449）から取りに行くだけである（エッジの設計概要 決定事項 9）。

## 2. 範囲

| 区分 | 内容 |
|---|---|
| 対象 | CA の作成（サーバーCA、テナントのクライアントCA）と発行の停止、CSR への署名（プロファイル）、証明書の一覧と検索、失効、CRL の作成と配布、期限の監視、運用者向けの画面、管理API（mTLS）、暗号化の鍵（KEK）の作成と入れ替え、バックアップ |
| 対象外 | ACME / SCEP / EST、OCSP、HSM（PKCS#11）、被発行者の鍵を本CA で作ること（PKCS#12）、中間CA・相互署名、CA の鍵の作り直し（re-key）と CA 証明書の更新（10 年の期限の前に別に検討する）、複数台・冗長化、CRL の差分（delta CRL）、証明書の透明性（CT） |

## 3. 決定事項

エッジの設計概要の決定事項のうち、本CA に関わるもの。

| # | 内容 | 決定日 |
|---|---|---|
| 1 | CA はエッジの外に置き、独立した CA にする。Go で自作し、署名の部分は内部のインターフェースの裏に置いて、後で OpenBao の PKI などに差し替えられるようにする（エッジの決定事項 6） | 2026-10-18 |
| 2 | AP の証明書を発行する CA（テナントのクライアントCA）は、テナントごとの自己署名の CA にする（共通のルートの下の中間CA にしない）（エッジの決定事項 7） | 2026-10-18 |
| 3 | CRL は、エッジがトンネルの中で本CA から取りに行く（エッジの決定事項 9） | 2026-10-18 |
| 4 | リポジトリは `radsec-ca`。AP の証明書は、最初は AP が作った CSR への署名だけにする（PKCS#12 は作らない）。DB は SQLite（`modernc.org/sqlite`）。画面の認証は Cloudflare Tunnel と Access（エッジの決定事項 10。エッジの設計概要 §19 の 2・5・6・7） | 2026-10-18 |
| 5 | テナントのサーバー証明書の SAN は、`primary` / `secondary` / `tertiary` の 3 つの名前を明示する（ワイルドカードは使わない）。エッジは AP の証明書を SAN の URI だけで照合する（エッジの決定事項 11。§18.2 の 1・6） | 2026-10-18 |
| 6 | §17 の確認事項 1〜10 は、すべて推奨案とする。エッジの設計概要に §16 の直しを反映した（エッジの決定事項 12） | 2026-10-18 |
| 7 | §18 の確認事項 1〜4（段階 2 の進め方）は、すべて推奨案とする。simwifi での導入の通しは段階 3 にまとめる（§15） | 2026-10-18 |
| 8 | MVP セットのために、テナント専用の持ち込みの CA（自己署名に限る。CRL 必須）を登録し、その CRL を取り直して（またはアップロードを受けて）今の配布の口で配る。Box の証明書（`box-client`）を発行する（§19。エッジの決定事項 18）（決定事項 9 で改めた） | 2026-10-20 |
| 9 | 持ち込みの CA は、自己署名でない CA（Meraki の RadSec 用の CA）も受ける（エッジは `PartialChain` で起点にする）。同じ CA を別のテナントに登録することは断る。CRL の取得先に Meraki の Dashboard API と「なし」（了承を記録し、エッジはそのテナントを `CRLCheck off` にする）を足す。Box の証明書を、AP のグループで共有するグループの証明書（`group-client`、SAN `urn:<接頭辞>:grp:...`）に広げる（§19。エッジの決定事項 19、aka-mvpset の決定事項 31〜35） | 2026-10-21 |

## 4. 技術方針

- 言語: Go 1.27.2。標準ライブラリを優先する（`crypto/x509`、`crypto/ecdsa`、`crypto/aes`・`crypto/cipher`、`net/http` のメソッドつき ServeMux、`html/template`、`embed`、`log/slog`、`encoding/json/v2`）。
- 外部依存（Go）: `modernc.org/sqlite`（cgo の要らない SQLite のドライバー）だけ。JWT の検証（RS256）、JWKS の取得、スキーマの移行は、OSS/BSS のものをコピーして手直しする（共有モジュールにはしない）。
- module パス: `github.com/oyaguma3/radsec-ca`。コマンド名は `radsec-ca`。設定は環境変数で受け取り、接頭辞は `CA_`。
- 画面: OSS/BSS と同じ Go + htmx + daisyUI（JavaScript は書かない）。
- 待ち受け（エッジの設計概要 §4 の表のとおり）:

| 口 | ポート | 待ち受けるアドレス | 認証 |
|---|---|---|---|
| 画面 | 8448（HTTP） | compose のネットワークの中（cloudflared からだけ受ける） | Cloudflare Access の JWT と、本CA の利用者の役割（§10） |
| 管理API | 9448（HTTPS） | トンネルのアドレス | mTLS。クライアント証明書のフィンガープリント（§9.1） |
| 配布 | 8449（HTTP） | トンネルのアドレス | なし（CA の証明書と CRL は署名つきで公開してよい情報） |

- 配備: Docker Compose（本CA と cloudflared）。コンテナは distroless の nonroot。DB はボリューム、KEK は Docker の secrets（ファイル）で渡す。
- イメージは公開しない（利用者はタグからソースでビルドする）。
- コードのコメントとドキュメントは日本語で書く。ブランチは `main` に直接コミットする（エッジと同じ）。

## 5. CA とプロファイル

### 5.1 CA

| CA | ID | 数 | Subject | 鍵 | 有効期限 | 署名するプロファイル |
|---|---|---|---|---|---|---|
| サーバーCA | `server` | 1 つ（初期化のときに作る） | CN `<組織> RadSec server CA`、O `<組織>` | ECDSA P-256 | 10 年 | `tenant-server` |
| テナントのクライアントCA | `tenant.<slug>` | テナントごと | CN `<slug> client CA`、O `<組織>` | ECDSA P-256 | 10 年 | `ap-client`、`probe-client` |

- どちらも自己署名。`BasicConstraints` は CA で `pathlen:0`（下に CA を作れない）、`KeyUsage` は `keyCertSign` と `cRLSign`。Subject Key Identifier を付ける。
- CA の ID のテナントの部分は slug（エッジの設計概要 §8.1。英小文字・数字・`-`）。`.` は slug に入らないので、`tenant.<slug>` は一意に読める。slug は SAN と NAS-Identifier に入るので、変えない。
- CA の状態は `active`（発行できる）と `disabled`（発行しない。CRL の作成と配布は続ける。§7.4）。
- `<組織>` は環境変数 `CA_ORG` で与える。

### 5.2 プロファイル

呼び出し側が渡すのは、プロファイルの名前と、名前の材料（テナント、AP、エッジ）と CSR だけである。署名する CA もプロファイルとテナントから決まる。

| プロファイル | 材料 | 署名する CA | CN | SAN | EKU | 有効期限 |
|---|---|---|---|---|---|---|
| `ap-client` | テナント、AP | `tenant.<テナント>` | `<テナント>-<AP>`（NAS-Identifier と同じ） | URI `urn:<接頭辞>:nas:<テナント>:<AP>` | clientAuth | 730 日 |
| `probe-client` | テナント、エッジ | `tenant.<テナント>` | `<テナント>-probe` | URI `urn:<接頭辞>:nas:<テナント>:probe` | clientAuth | 730 日 |
| `tenant-server` | テナント、エッジ | `server` | `<テナント> server <エッジ>` | DNS `primary.<テナント>.<ドメイン>`、`secondary.<テナント>.<ドメイン>`、`tertiary.<テナント>.<ドメイン>` | serverAuth | 365 日 |

- `<接頭辞>` は `CA_URN_PREFIX`、`<ドメイン>` は `CA_DNS_DOMAIN` で与える。どちらもエッジと OSS/BSS の設定と同じ値にそろえる（運用でそろえ、`/status` に出して目で比べられるようにする）。
- 名前の材料は、エッジの設計概要 §8.1 の規則（`^[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?$`）で検証する。エッジの ID も同じ規則とする。
- AP の名前 `probe` は予約で、`ap-client` では断る（`probe-client` だけが使う。エッジの設計概要 §11.3）。
- `probe-client` の証明書は、テナントとエッジの組ごとに発行する（鍵はエッジで作る）。SAN はテナントの中で同じで、エッジの client ブロックは 1 つで済む。
- `KeyUsage` は `digitalSignature`（RSA の鍵なら `keyEncipherment` も）。Authority Key Identifier を付ける。CRL の配布点（CDP）の拡張は付けない（radsecproxy は CRL を自分で取りに行かないため）。
- 有効期限は CA の期限を超えない（超えるなら CA の期限で切る）。`NotBefore` は時計のずれを見込んで 5 分前にする。
- 有効期限の値は、AP の機種での確認（エッジの設計概要 §18 の V7。後回し）の結果で見直す。環境変数で変えられるようにする（`CA_AP_CERT_DAYS` など。§12）。

### 5.3 CSR の扱い

- PEM の CSR（`CERTIFICATE REQUEST`）を 1 つだけ受け付ける（16 KB まで）。CSR の自己署名を確かめる（`CheckSignature`）。
- **使うのは公開鍵だけ**とする。CSR の Subject、SAN、拡張の要求はすべて無視する（好きな SAN を書いた CSR による成りすましを防ぐ）。
- 受け付ける公開鍵: ECDSA P-256 / P-384、RSA 2048〜4096 ビット。それ以外（Ed25519 など）は断る（AP と radsecproxy の対応が確かでないため）。
- 同じ公開鍵の有効な証明書がすでにあっても断らない（更新で同じ鍵を使う AP がありうる）。記録には公開鍵の SHA-256 を残す。

### 5.4 シリアル番号と署名

- シリアル番号は 128 ビットの乱数（正の値）。DB で全体の一意を確かめ、重なったら作り直す。
- 署名のアルゴリズムは、CA の鍵が ECDSA P-256 なので ECDSA with SHA-256。

## 6. 鍵の保管

### 6.1 暗号化

- CA の秘密鍵は PKCS#8 の DER を AES-256-GCM で暗号化して DB に入れる。nonce は 12 バイトの乱数、AAD は CA の ID（暗号文を別の CA の行に移しても復号できないようにする）。
- 暗号化の鍵（KEK）は 32 バイトの乱数で、ファイル（`CA_KEK_FILE`。Docker の secrets）で渡す。DB には KEK の識別子（SHA-256 の先頭 8 バイトの 16 進）だけを持つ。
- 鍵は署名のたびに復号して使い、メモリーに持ち続けない。

### 6.2 起動のときの確認

- KEK のファイルを読めない、32 バイトでない、識別子が DB と合わない場合は起動しない。
- すべての CA の鍵を復号し、証明書の公開鍵と合うことを確かめる。合わなければ起動しない（ログにその CA の ID を出す）。

### 6.3 KEK の入れ替えとバックアップ

- `radsec-ca rotate-kek -old <ファイル> -new <ファイル>`: すべての CA の鍵を新しい KEK で暗号化し直す（1 つのトランザクション）。止めてから行う。
- `radsec-ca backup -out <ファイル>`: SQLite の `VACUUM INTO` で、動かしたまま DB の写しを作る。DB には平文の鍵はないが、KEK と一緒に置かない。
- KEK は DB とは別の場所に、オフラインで保管する。**KEK を失うと、すべての CA を作り直し、すべての証明書を出し直すことになる**（運用ガイドに書く）。

### 6.4 署名の部分の差し替え

署名は内部のインターフェースの裏に置く。

```go
// Signer は CA の鍵による署名を受け持つ（今は DB の暗号化した鍵。後で OpenBao の PKI や HSM に差し替える）。
type Signer interface {
	CreateCA(ctx context.Context, id string, subject pkix.Name, validity time.Duration) (*x509.Certificate, error)
	SignCertificate(ctx context.Context, caID string, tmpl *x509.Certificate, pub crypto.PublicKey) (*x509.Certificate, error)
	CreateCRL(ctx context.Context, caID string, tmpl *x509.RevocationList) ([]byte, error)
}
```

## 7. 失効と CRL

### 7.1 失効

- 失効は証明書のシリアル番号で行う。理由は `unspecified`、`keyCompromise`、`superseded`（更新した）、`cessationOfOperation`（AP やテナントをやめた）から選ぶ。
- 失効させたら、その CA の CRL をすぐ作り直す（§7.2）。
- 失効は取り消せない（`certificateHold` は使わない）。間違えて失効させたら、新しい証明書を発行する。
- 同じ証明書をもう一度失効させても成功として扱い、何もしない（理由も変えない）。

### 7.2 CRL の作り方

| 項目 | 値 |
|---|---|
| 版 | X.509 v2 CRL。CRL の番号（`cRLNumber`）を CA ごとに 1 ずつ増やす |
| thisUpdate | 作った時刻 |
| nextUpdate | thisUpdate の 7 日後（`CA_CRL_VALIDITY`） |
| 作り直す時 | 失効させたとき、前の CRL から 1 日（`CA_CRL_REFRESH`）経ったとき、起動したときに nextUpdate までが 1 日を切っていたとき |
| 載せるもの | 失効させた証明書のうち、有効期限が切れていないもの（期限の切れた証明書は載せない。RFC 5280 で許される） |
| 保存 | 作った CRL を DB に残す（CA ごとに直近の 30 個） |

- 作り直しは、本CA の中の定期の処理（1 分ごとに確かめる）で行う。作り直せなかったら ERROR のログを出し、`/status` と画面に出す。
- **nextUpdate を 7 日にするのは、中央が止まっても 7 日はエッジが新しい接続を受けられるようにするため**（エッジの設計概要 §9.5、§18.1 の V2）。本CA が止まっている時間が 6 日を超えると、エッジは警告（残り 3 日）を出し始める。

### 7.3 配布（8449）

| 口 | 内容 |
|---|---|
| `GET /ca/{caId}.pem` | CA の証明書（PEM） |
| `GET /crl/{caId}.pem` | その CA の最新の CRL（PEM。エッジは CA の証明書とつないで radsecproxy の `CACertificateFile` に入れる） |
| `GET /crl/{caId}.der` | 同じ CRL（DER） |

- 応答に `ETag`（CRL の番号と CA の ID から作る）と `Last-Modified` を付け、`If-None-Match` には 304 を返す。エッジは 5 分ごとに取りに来るので、変わっていないときは本文を送らない。
- `Cache-Control: max-age=60`。
- 待ち受けはトンネルのアドレスだけ。中身は公開してよい情報なので、クライアント認証はしない。CRL の改ざんは、エッジが CA の証明書で CRL の署名を確かめることで防ぐ。

### 7.4 テナントをやめるとき

- テナントのクライアントCA を `disabled` にし、そのテナントの有効な証明書をすべて `cessationOfOperation` で失効させる（`POST /cas/{caId}/disable`）。
- `disabled` の CA の CRL も、載せる証明書の期限が切れるまで作り続け、配布する（エッジからテナントを消し終わるまでの間も、CRL の期限を切らさないため）。
- CA の行は消さない（記録として残す）。

## 8. データ

SQLite（WAL）。スキーマの移行は OSS/BSS と同じ自前の仕組み（版の番号の表と、版ごとの SQL を `embed`）。

| 表 | 主な項目 |
|---|---|
| `cas` | `id`（`server` / `tenant.<slug>`）、`kind`（`server` / `tenant-client`）、`tenant`、`cert_der`、`key_enc`、`key_nonce`、`kek_id`、`status`（`active` / `disabled`）、`crl_number`、`not_after`、`created_at`、`disabled_at` |
| `certs` | `serial`（16 進。全体で一意）、`ca_id`、`profile`、`tenant`、`ap`、`edge`、`cn`、`san_dns`、`san_uri`、`not_before`、`not_after`、`cert_der`、`pubkey_sha256`、`revoked_at`、`revoke_reason`、`issued_by`（操作者）、`trace_id`、`created_at` |
| `crls` | `ca_id`、`number`、`this_update`、`next_update`、`der`、`created_at` |
| `users` | `email`、`role`（`admin` / `viewer`）、`enabled`、`created_at`（画面の利用者。§10） |
| `audit` | `id`、`time`、`operator`、`mgmt_client`（API のとき）、`source`（`api` / `gui` / `cli`）、`action`、`target`、`trace_id`、`result`、`details` |
| `idempotency` | `mgmt_client`、`key`、`req_hash`、`status`、`response`、`expires_at`（§9.2） |

- 索引: `certs(tenant, profile, ap)`、`certs(not_after)`（期限の近いもの）、`certs(ca_id, revoked_at)`（CRL を作るとき）。
- 証明書の記録は消さない（期限が切れても残す）。

## 9. 管理API（9448、mTLS）

項目の詳細は OpenAPI（`docs/openapi/ca-api.yaml`）で定める。本書では口の一覧と方針だけを書く。

### 9.1 認証・ヘッダー・エラー

- mTLS 必須。管理クライアントは `CA_ADMIN_CLIENTS`（`識別名=フィンガープリント,...`）で静的に設定する（provisioner の `PROVISIONER_ADMIN_CLIENTS` と同じ形）。識別名は監査ログの `mgmt_client` になる。空なら API を待ち受けない（単独モードで画面だけを使う場合）。
- サーバー証明書は自己署名（ファイルがなければ起動時に作り、ボリュームに保存する。SAN は `CA_TLS_HOSTS`）。`radsec-ca server-cert` で PEM とフィンガープリントを表示し、provisioner に検証用として渡す。本CA の発行する証明書とは別のものである（エッジの設計概要 §9.1）。
- TLS 1.2 以上。
- `X-Operator-Id`（`^[A-Za-z0-9._@-]{1,64}$`）、`X-Trace-ID`（受け取るか採番し、応答のヘッダーで返す）。
- エラーは ProblemDetails（`application/problem+json`）で、`cause` に理由の符号を入れる（provisioner と同じ）。主な `cause`: `VALIDATION_ERROR`、`CSR_INVALID`、`KEY_TYPE_UNSUPPORTED`、`NAME_RESERVED`、`CA_NOT_FOUND`、`CA_EXISTS`、`CA_DISABLED`、`CERT_NOT_FOUND`、`IDEMPOTENCY_CONFLICT`、`SYSTEM_FAILURE`。

### 9.2 冪等

証明書の発行は、同じ要求を 2 回送ると 2 枚できてしまう。発行・失効・CA の作成と停止には `Idempotency-Key` を必須とし、同じ鍵・同じ本文の再送には前の応答を返す（本文が違えば 409 `IDEMPOTENCY_CONFLICT`）。保持は 24 時間。provisioner の再送の判定と同じ考え方である。

### 9.3 口

| 口 | 内容 |
|---|---|
| `GET /status` | 版、KEK の識別子、CA の数、CA ごとの状態・期限・最新の CRL の番号と nextUpdate・作り直しの失敗、期限の近い証明書の数（30 日以内）、`CA_URN_PREFIX` と `CA_DNS_DOMAIN` |
| `GET /cas` / `GET /cas/{caId}` | CA の一覧と詳細（証明書の PEM を含む） |
| `POST /cas` | テナントのクライアントCA の作成（本文: `tenant`）。あれば 409 `CA_EXISTS` |
| `POST /cas/{caId}/disable` | テナントをやめる（§7.4） |
| `POST /certs` | 発行（本文: `profile`、`tenant`、`ap` または `edge`、`csr`）。応答: シリアル番号、証明書の PEM、有効期限、署名した CA の ID と証明書の PEM |
| `GET /certs` | 一覧（絞り込み: `tenant`、`profile`、`ap`、`edge`、`status`=`valid` / `revoked` / `expired`、`expiresBefore`）。ページ送りつき |
| `GET /certs/{serial}` | 詳細 |
| `POST /certs/{serial}/revoke` | 失効（本文: `reason`）。CRL をすぐ作り直す |
| `GET /cas/{caId}/crl` | 最新の CRL の番号・thisUpdate・nextUpdate と PEM（配布の口と同じ中身。provisioner から確かめるため） |

エッジの設計概要 §12.2 の口の名前（`POST /cas/{caId}/sign`、`/cas/{caId}/certs/{serial}/revoke`、`GET /crl/{caId}`）は、本書の形に直す（§16）。

## 10. 画面（8448）

### 10.1 認証と役割

- OSS/BSS と同じく、Cloudflare Access の JWT を検証し、メールアドレスで本CA の利用者を引く（`CA_ACCESS_TEAM_DOMAIN`、`CA_ACCESS_AUD`）。
- 役割は 2 つ。`admin`（すべての操作）と `viewer`（見るだけ）。Access のポリシーで本CA の担当者だけを許し、本CA の中でも役割を分ける。
- 最初の管理者は `CA_INITIAL_ADMIN_EMAIL` で与える（起動のたびに `admin`・有効に戻す。締め出されたときに戻す経路。OSS/BSS と同じ）。
- CSRF 対策は `CrossOriginProtection`。サーバー側のセッションは持たない。

### 10.2 画面の一覧

| 画面 | 内容 | 役割 |
|---|---|---|
| ダッシュボード | CA ごとの状態・期限・CRL の番号と nextUpdate（作り直しの失敗の警告）、期限の近い証明書の数、KEK の識別子、設定（接頭辞、ドメイン） | 両方 |
| CA の一覧・詳細 | CA の証明書の表示と取り出し、発行した証明書の数、CRL の履歴、テナントのクライアントCA の作成、停止 | 作成・停止は `admin` |
| 証明書の一覧・詳細 | 絞り込み（テナント、プロファイル、状態、期限の近いもの）、証明書の取り出し、失効 | 失効は `admin` |
| 署名（単独モード） | プロファイルと名前の材料を選び、CSR を貼り付けて署名し、証明書を取り出す。エッジの画面から取り出した CSR（サーバー・probe）と、AP の CSR に使う | `admin` |
| 利用者 | 利用者の追加・役割の変更・無効化 | `admin` |
| 監査ログ | 操作の記録 | 両方 |

管理モードでも、署名と失効の画面は使える（緊急の失効のため）。そのときは OSS/BSS の AP の台帳とずれるので、画面に「OSS/BSS の側でも処理すること」と出し、監査ログに残す。

## 11. 主な流れ

### 11.1 管理モード（provisioner から）

エッジの設計概要 §14 の流れのうち、本CA が受け持つ部分。

| 流れ | 本CA への要求 |
|---|---|
| テナントの RadSec の有効化（§14.2） | `POST /cas`（`tenant`） |
| テナントをエッジに置く（§14.2） | エッジが作った CSR で `POST /certs`（`tenant-server`、`probe-client`。どちらも `tenant`・`edge`） |
| AP の登録（§14.3） | AP が作った CSR で `POST /certs`（`ap-client`、`tenant`・`ap`） |
| AP の削除（§14.4） | `POST /certs/{serial}/revoke`（`cessationOfOperation`）。その後、provisioner がエッジに `crl:refresh` を送る |
| 証明書の更新（§14.5） | 新しい CSR で `POST /certs`、古い証明書を `superseded` で失効 |
| テナントをやめる | `POST /cas/{caId}/disable` |

- エッジに渡す CA の証明書（テナントのクライアントCA）は、`POST /cas` と `GET /cas/{caId}` の応答の PEM を provisioner が中継する。エッジは CRL を配布の口から取る。
- AP に設定するサーバーCA の証明書は、OSS/BSS の画面から取り出せるようにする（`GET /cas/server`）。

### 11.2 単独モード（運用者が画面で）

1. 本CA の画面でテナントのクライアントCA を作り、CA の証明書を取り出してエッジの画面に取り込む。
2. エッジの画面から取り出したサーバーの CSR と probe の CSR を、本CA の画面で署名し、エッジの画面に取り込む。
3. AP の CSR を本CA の画面で署名し、AP に入れる。エッジの画面で AP を登録する（名前は同じものを入れる）。
4. 失効は本CA の画面で行う。エッジは CRL を取りに来るので、エッジの側の操作は要らない（すぐ効かせたいときはエッジの画面で CRL の取り直しをする）。

単独モードでも、エッジから本CA の配布の口（8449）に届く経路（トンネル）が要る。

## 12. 設定（環境変数）

| 名前 | 内容 | 既定 |
|---|---|---|
| `CA_ORG` | CA の Subject の O と CN に入れる組織の名前 | — （必須） |
| `CA_URN_PREFIX` | SAN の URI の接頭辞（`urn:<接頭辞>:nas:...`） | — （必須） |
| `CA_DNS_DOMAIN` | サーバー証明書の SAN のドメイン（`primary.<テナント>.<ドメイン>`） | — （必須） |
| `CA_DB_PATH` | SQLite のファイル | `/data/radsec-ca.db` |
| `CA_KEK_FILE` | KEK のファイル | `/run/secrets/kek` |
| `CA_ADMIN_CLIENTS` | 管理クライアント（`識別名=フィンガープリント,...`） | 空（API を待ち受けない） |
| `CA_TLS_HOSTS` | 管理API のサーバー証明書の SAN | — |
| `CA_API_ADDR` / `CA_PUBLISH_ADDR` / `CA_GUI_ADDR` | 待ち受けのアドレス | `:9448` / `:8449` / `:8448` |
| `CA_ACCESS_TEAM_DOMAIN` / `CA_ACCESS_AUD` / `CA_INITIAL_ADMIN_EMAIL` | 画面の認証（§10.1） | — |
| `CA_AP_CERT_DAYS` / `CA_SERVER_CERT_DAYS` | 有効期限（§5.2） | `730` / `365` |
| `CA_CRL_VALIDITY` / `CA_CRL_REFRESH` | CRL の nextUpdate と作り直しの間隔（§7.2） | `168h` / `24h` |
| `LOG_LEVEL` | ログの段階 | `INFO` |

コマンド: `radsec-ca serve`（既定）、`radsec-ca gen-kek -out <ファイル>`、`radsec-ca rotate-kek`、`radsec-ca backup`、`radsec-ca server-cert`。初めて起動したときに、DB の作成、サーバーCA の作成、最初の管理者の作成を行う。

## 13. ログと監査ログ

- アプリケーションログは JSON（`log/slog`）で標準出力に出す。`event_id` を付ける（例: `CA_STARTED`、`CA_CERT_ISSUED`、`CA_CERT_REVOKED`、`CA_CRL_PUBLISHED`、`CA_CRL_FAILED`、`CA_KEK_MISMATCH`、`CA_AUTH_REJECTED`）。`trace_id` を付ける。
- 監査ログは DB の `audit` に残し、標準出力にも出す。残すのは、CA の作成・停止、発行、失効、利用者の変更、KEK の入れ替え、バックアップ。`details` には、プロファイル、名前の材料、シリアル番号、公開鍵の SHA-256 を入れる（CSR と証明書の本体は入れない）。
- 鍵、KEK、JWT はログに出さない。

## 14. 試験

| 層 | 内容 |
|---|---|
| 単体 | プロファイル（名前の材料から CN・SAN・EKU・期限が決まる、CSR の Subject と拡張を無視する、`probe` の予約、鍵の種類の制限、CA の期限で切る）、シリアル番号の一意、CRL（番号の増加、期限の切れた証明書を載せない、nextUpdate）、KEK（違う KEK・AAD の違う行は復号できない、起動のときの確認）、冪等（同じ鍵・違う本文） |
| 結合 | SQLite を使った API（mTLS とフィンガープリント、ProblemDetails、`Idempotency-Key`）、配布の口（`ETag` と 304）、`rotate-kek`、`backup` から戻して起動できること、画面（JWT の検証、役割、CSRF） |
| 相互運用 | `openssl verify -CAfile` で発行した証明書を検証、`openssl verify -crl_check` で失効を検証、`openssl crl -text` で CRL の中身を確かめる。radsecproxy が受け付けることは、エッジの E2E（エッジの設計概要 §17）で確かめる |

## 15. 進め方（案）

エッジの設計概要 §20 の段階 2 に当たる。

| 手順 | 内容 | 終わりの確かめ |
|---|---|---|
| 1 | 本書の確認事項の合意 | — |
| 2 | 土台（設定、SQLite とスキーマの移行、KEK、CA の作成、`Signer`、プロファイル、CLI） | 単体の試験 |
| 3 | 失効と CRL、配布の口、定期の処理 | 単体・結合の試験、`openssl verify -crl_check` |
| 4 | 管理API（mTLS、冪等、監査ログ） | 結合の試験 |
| 5 | 画面（Cloudflare Access、役割、各画面） | 結合の試験、simwifi |
| 6 | 運用ガイド（導入、KEK とバックアップ、戻し方）、README、配備（Dockerfile、compose、CI） | 手元の compose。simwifi での導入の通しは、エッジと CA をつなぐ段階 3 にまとめる（§18 の 1） |

手順 2〜6 は 2026-10-18 に終えた（単体・結合・相互運用の試験は CI で動かす。手元の compose で、KEK の secrets、管理API、配布の口、画面、バックアップを確かめた）。

## 16. エッジの設計概要への反映（2026-10-18 に反映した）

- §12.2 の口の名前を本書 §9.3 に合わせる（`POST /certs`、`POST /certs/{serial}/revoke`、配布の口は `GET /crl/{caId}.pem`・`GET /ca/{caId}.pem`）。
- §12.1 に、probe の証明書の口（`POST /tenants/{tenantId}/probe-csr`、`PUT /tenants/{tenantId}/probe-cert`）を足す。サーバー証明書と同じく、鍵はエッジで作って外に出さない。
- §9.5 と §11.2 に、エッジは取ってきた CRL の署名を CA の証明書で確かめてから置くことを足す（配布の口はクライアント認証をしないため）。
- §7.3（CA の SQLite）と §12.2 は本書を参照する形にして、重複を減らす。

## 17. 確認事項（2026-10-18 にすべて推奨案で合意）

1. CA の ID: `server` と `tenant.<slug>`（推奨。人が読める。slug は変えないので ID にしてよい）。UUID にする方法もある。
2. 発行の口: `POST /certs` にプロファイルと名前の材料を渡し、署名する CA は本CA が決める（推奨。呼び出し側が CA を取り違えない）。エッジの設計概要 §12.2 の `POST /cas/{caId}/sign` から変える。
3. ヘルスチェック用の証明書: 予約した名前 `probe` で、テナントとエッジの組ごとに発行し、鍵はエッジで作る（推奨）。エッジの API に CSR の口を足す（§16）。
4. 受け付ける鍵: ECDSA P-256 / P-384、RSA 2048〜4096。Ed25519 は断る（推奨）。
5. CRL: PEM と DER で配布し、`ETag` で変わっていないときは送らない。期限の切れた証明書は載せない（推奨）。nextUpdate 7 日・作り直し 1 日はエッジの設計概要のとおり。
6. テナントをやめるとき: CA を `disabled` にし、有効な証明書をすべて失効させ、CRL は作り続ける（推奨）。
7. 画面の役割: 本CA に利用者の表を持ち、`admin` / `viewer` の 2 つに分ける（推奨）。Access のポリシーだけで済ませ、役割を分けない方法もある。
8. KEK の入れ替え（`rotate-kek`）とバックアップ（`backup`）のコマンドを最初から作る（推奨。小さく作れ、鍵の運用の要になるため）。
9. 冗長化はしない（推奨）。本CA が止まっても、発行と失効ができないだけで、認証は止まらない。CRL の nextUpdate（7 日）の間に戻す。
10. CA の鍵の作り直しと CA 証明書の更新（10 年）は対象外とし、期限の前に別に検討する（推奨）。

## 18. 段階 2 の確認事項（2026-10-18 にすべて推奨案で合意）

1. simwifi での導入の通しは、エッジと CA をつないだ単独モードの通し（エッジの設計概要 §20 の段階 3）にまとめる。段階 2 は手元の compose での確かめまでとし、運用ガイドは段階 2 で下書きして段階 3 で手直しする。
2. openssl による相互運用の試験（`verify -CAfile`、`verify -crl_check`、`crl -text`）は Go の試験として書き、`CA_TEST_OPENSSL=1` のときだけ動かす。CI では必ず動かし、スキップされたら失敗にする。発行した証明書と CRL を radsec-edge の検証の規則が受け付けることも、ここで突き合わせる。
3. OpenAPI（`docs/openapi/ca-api.yaml`）は §15 の手順 4 で書き、実装の口と OpenAPI のパスがずれないことを試験で確かめる（段階 4 で provisioner が呼ぶときの契約になる）。
4. コミットと push は、§15 の手順（2〜6）ごとに `main` に行う。CI（GitHub Actions）は手順 2 で足す。

## 19. MVP セットのための変更（持ち込みの CA とグループの証明書）

### 19.1 背景

- エッジと本CA を、VPS に分けて置いて顧客を収容できる MVP セット（[aka-mvpset](https://github.com/oyaguma3/aka-mvpset)）に組み入れる。2026-10-20 に、業者の CA の証明書を使う AP と、RadSec に対応しない AP をまとめる Box を受けることにした（本書の決定事項 8）。
- 2026-10-21 に、業者の製品の調べとラボ（aka-mvpset の `verify/r10/`）をもとに改めた（本書の決定事項 9。aka-mvpset の決定事項 31〜35、エッジの設計概要 §24・決定事項 19）。主な点は、Meraki の新しい CA（PureCA）が自己署名でない中間 CA であること、Mist の組織の CA が CRL を出すか分からないこと、証明書を AP のグループで共有する製品（UniFi、Extreme など）が多いこと。
- 本CA の変更は 2 つ: テナント専用の**持ち込みの CA** を登録して、その CRL を配ること（CRL のない CA も印を付けて登録できる）と、**グループの証明書**を発行すること。

### 19.2 持ち込みの CA

| 項目 | 内容 |
|---|---|
| ID | `brought.<slug>.<名前>`（名前はエッジの設計概要 §8.1 の規則。`.` は slug と名前に入らないので一意に読める） |
| 種類 | `cas.kind` = `tenant-brought`。CA の証明書だけを持ち、鍵は持たない（本CA は署名しない） |
| 登録のときの確かめ | PEM の CA の証明書が 1 つ。`BasicConstraints` が CA、`KeyUsage` に `keyCertSign`、有効期限の中。自己署名か否かを記録する（自己署名でない CA は、エッジで `PartialChain on` にして起点にする。エッジの設計概要 §24.5） |
| テナント専用 | 登録する人が「このテナント専用の CA であることを確かめた」と明示し、監査ログに残す。**同じ CA（証明書の SHA-256 フィンガープリント）を別のテナントに登録することは断る**（1 テナント = 1 業者の組織）。全顧客で共通の CA は受けない |
| CRL の取得先 | `url`（URL から取る）、`meraki`（Meraki の Dashboard API から取る）、`upload`（アップロードを受ける）、`none`（CRL がない）のどれか（§19.3） |
| 状態 | `active` / `disabled`。`disabled` にしても、エッジからテナントの CA を外し終わるまで CRL の取得と配布を続ける（§7.4 と同じ考え方） |

- 自己署名でない CA を受けるのは、エッジの radsecproxy に `PartialChain` のパッチを当てたためである（エッジの設計概要 §24.5）。束に置くのはその CA だけで、上位の CA（業者の共通のルートなど）は置かない（置くと、他の顧客の証明書も検証を通るため）。
- 業者の CA の入れ替え（Meraki の Keeper から PureCA への移行のような）に備え、同じテナントに複数の持ち込みの CA を登録できる。

### 19.3 持ち込みの CA の CRL

| 取得先 | 取り方 |
|---|---|
| `url` | `CA_BROUGHT_CRL_REFRESH`（案: 1 時間）ごとに取りに行く（`If-None-Match` / `If-Modified-Since`、タイムアウトは `CA_BROUGHT_CRL_TIMEOUT`、案: 30 秒）。HTTP と HTTPS の両方を受ける（CRL は署名で守られるため） |
| `meraki` | Meraki の Dashboard API の `GET /organizations/{organizationId}/wireless/devices/radsec/certificates/authorities/crls`（`certificateAuthorityIds` で絞れる）を、同じ間隔で呼ぶ。応答の `items` の中から、登録した CA が発行した CRL（発行者と署名で照合する）を選ぶ。差分の CRL（`.../crls/deltas`）は使わない（エッジの radsecproxy が差分の CRL を使わないため）。組織の ID と API キー（顧客に読み取り専用の管理者のキーを出してもらう）を登録し、API キーは KEK で暗号化して持つ |
| `upload` | 管理API（`PUT /cas/{caId}/crl`）か画面から、PEM か DER の CRL を受ける |
| `none` | CRL を配らない。エッジはそのテナントを `CRLCheck off` にし、共通のブロックを業者の証明書の形で絞る（エッジの設計概要 §24.3）。登録する人が「CRL がなく、業者の AP の失効が効かないこと」を了承したと明示し、監査ログに残す |

- `url`・`meraki`・`upload` では、置く前に次を確かめる: 持ち込みの CA の証明書で署名が検証できる、nextUpdate が未来、`cRLNumber` があれば今の CRL の番号より小さくない。通らなければ置かずに今の CRL を残し、`/status` と画面に出す。
- 本CA は持ち込みの CRL に署名し直さず、受け取ったものをそのまま `crls` に残して、今の配布の口（`GET /crl/{caId}.pem` / `.der`。§7.3）で配る。エッジは今と同じく CA の証明書で署名を確かめる。`ETag` は CRL の中身のハッシュから作る。
- nextUpdate までの残りが閾値（案: 3 日。業者の CRL の nextUpdate がそれより短いときは、その半分）を切ったら、`/status` と画面で警告する。取得の失敗が続いたときも同じ。
- `url` と `meraki` では、管理面のノードから業者の口へ外向きに出る通信を、ファイアウォールで許す必要がある。
- Meraki の CRL の中身（どの CA の CRL が返るか、nextUpdate の長さ、AP を組織から外したときに失効として載るか）は、実機の組織で確かめるまで推定である（aka-mvpset の概要 §19）。

### 19.4 グループの証明書

| プロファイル | 材料 | 署名する CA | CN | SAN | EKU | 有効期限 |
|---|---|---|---|---|---|---|
| `group-client` | テナント、グループ | `tenant.<テナント>` | `<テナント>-<グループ>` | URI `urn:<接頭辞>:grp:<テナント>:<グループ>` | clientAuth | 730 日（`CA_GROUP_CERT_DAYS`） |

- 1 枚の証明書を、AP のグループ（UniFi の RADIUS のプロファイル、Extreme の Trust Point、Aruba の AP グループ、Mist の組織）や Box で共有して使う（aka-mvpset の概要 §9.3）。
- グループの名前はエッジの設計概要 §8.1 の AP の名前と同じ規則。`probe` は予約。テナントの中で AP の名前と重ならないことは OSS/BSS が保証する（CN が同じになるため）。
- 鍵は顧客が作り、CSR を出してもらう（本CA は鍵を作らない）。CSR の扱い（§5.3）、失効（§7.1）は AP の証明書と同じ。
- 更新は同じグループの名前で発行し直す（SAN が同じなので、エッジの設定は変わらない）。顧客が入れ替えた後で古い証明書を `superseded` で失効させる。グループを消すときは `cessationOfOperation`、鍵が漏れたときは `keyCompromise` で失効させる。
- 本CA が発行するのは、登録した AP・グループ・probe の証明書だけにする。登録の台帳は OSS/BSS にあるので、provisioner を通した発行（`POST /certs`）は OSS/BSS の登録の流れからだけ呼ばれる。

### 19.5 データ・API・設定の変更

| 対象 | 変更 |
|---|---|
| `cas` | `kind` に `tenant-brought` を足す（`key_enc`・`key_nonce`・`kek_id` は空）。`self_signed`、`fingerprint_sha256`（全体で一意）、`crl_source`（`issued` / `url` / `meraki` / `upload` / `none`）、`crl_url`、Meraki の組織の ID と暗号化した API キー、取得の状態（`ETag`、最後に試みた時刻と結果）、テナント専用と CRL なしの了承をした操作者と時刻を足す |
| `certs` | `grp`（グループの名前。`profile` が `group-client` のとき）を足す |
| `crls` | 持ち込みの CA の CRL も同じ表に残す（`number` は `cRLNumber`。なければ空） |
| 管理API | `POST /cas` に持ち込みの CA の登録（本文: `tenant`、`kind`=`brought`、`name`、`certPem`、`crl`（`source` と、`url` か `merakiOrgId`・`merakiApiKey` か `pem`）、`tenantOnlyConfirmed`、`noCrlAccepted`）。`PUT /cas/{caId}/crl`（アップロード）。`POST /cas/{caId}/crl:refresh`（すぐ取りに行く）。`POST /certs` に `group-client`（`tenant`・`group`）。`GET /cas/{caId}` に自己署名か・CRL の有無を加える（エッジの `CRLCheck` と `PartialChain` を決めるのに使う）。`GET /status` に持ち込みの CA の CRL の状態 |
| 画面 | 持ち込みの CA の登録・一覧・停止、CRL の状態と取り直し・アップロード、グループの証明書の発行と失効 |
| 設定 | `CA_BROUGHT_CRL_REFRESH`（`1h`）、`CA_BROUGHT_CRL_TIMEOUT`（`30s`）、`CA_GROUP_CERT_DAYS`（`730`） |
| `cause` | `CA_FINGERPRINT_IN_USE`、`CRL_INVALID`、`CRL_REQUIRED`、`TENANT_ONLY_NOT_CONFIRMED`、`NO_CRL_NOT_ACCEPTED` を足す |

### 19.6 確かめたこと

V14（radsecproxy が自己署名でない CA を信頼の起点にできるか）は、aka-mvpset の `verify/r10/` のラボ（2026-10-20）で確かめた。無改造の radsecproxy（1.11.2、1.11.4）ではできない。`PartialChain` のパッチを当てた版ではでき、他の組織の証明書を拒否できる。ただし `CRLCheck on` と組み合わせるには、CRL の確認をリーフだけにする変更も要る。このとき要る CRL は、起点にした CA の CRL 1 つだけになる（Meraki では RadSec 用の CA を起点にする）。結果のまとめは aka-mvpset の概要 §20.2、エッジの設計概要 §24.7。

### 19.7 進め方

- エッジの段階 4 の中で、エッジの管理API（4-1）と並べて行う（4-2 で provisioner が中継する前に終える）。
- 本書の §5.1 の CA の表、§5.2 のプロファイルの表、§8 のデータ、§9.3 の口、§12 の設定への反映は、実装するときに行う。
