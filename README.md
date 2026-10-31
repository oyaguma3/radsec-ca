# radsec-ca

[radsec-edge](https://github.com/oyaguma3/radsec-edge)（RadSec の AP を受けるエッジノード）のための独立した CA です。AP のクライアント証明書と、エッジのサーバー証明書を発行し、CRL を作って配ります。

- テナント（AP のグループ）ごとに自己署名のクライアントCA を持ち、テナントの間で証明書が通らないようにします。
- 業者の CA を使う AP のために、テナント専用の持ち込みの CA を登録し、その CRL を取り直して配ります（URL、Meraki の Dashboard API、アップロード。CRL のない CA も印を付けて受けます）。証明書を AP のグループで共有する製品のために、グループの証明書も発行します。
- 証明書の CN・SAN・EKU・有効期限は、呼び出し側が渡す名前（テナント、AP、エッジ）から決まった規則で作ります。CSR から使うのは公開鍵だけです。
- CA の鍵は暗号化して保存します（AES-256-GCM。暗号化の鍵はファイルで渡す）。
- 運用者向けの Web GUI（Cloudflare Access）と、[aka-provisioner](https://github.com/oyaguma3/aka-provisioner) から呼ぶ管理API（mTLS）を持ちます。

## 状態

開発中です。CA の管理、署名、失効と CRL、配布の口、管理API、画面を作り、radsec-edge とつないだ単独モードの通しを確かめました。[MVP セット](https://github.com/oyaguma3/aka-mvpset)のための持ち込みの CA・グループの証明書・ピンのファイル・監査ログのファイルを足しました（段階 4-0）。管理モードの通しは MVP セットの段階 4 の終わりに確かめます。

- 設計概要: [docs/design-overview.md](docs/design-overview.md)
- 管理API: [docs/openapi/ca-api.yaml](docs/openapi/ca-api.yaml)
- 運用ガイド: [docs/operations.md](docs/operations.md)

## 口

| 口 | ポート | 内容 |
|---|---|---|
| 画面 | 8448（HTTP） | 運用者向け（Cloudflare Access）。CA と証明書の一覧、署名（単独モード）、失効、利用者（admin / viewer）、監査ログ |
| 管理API | 9448（HTTPS、mTLS） | aka-provisioner から（管理モード）。CA の作成・登録・停止、発行、失効、CRL の取得先と取り直し |
| 配布 | 8449（HTTP） | エッジから。`GET /ca/{caId}.pem`、`GET /crl/{caId}.pem`（`ETag` つき） |

CA の ID はサーバーCA が `server`、テナントのクライアントCA が `tenant.<slug>`、持ち込みの CA が `brought.<slug>.<名前>` です。プロファイルは `ap-client`（AP）、`group-client`（AP のグループ・Box）、`probe-client`（エッジのヘルスチェック）、`tenant-server`（エッジのサーバー証明書）の 4 つです。

## 配備

| ファイル | 内容 |
|---|---|
| `compose.yaml` | 土台（単独モード）。本CA と cloudflared |
| `compose.managed.yaml` | 管理モードで重ねる。管理API を aka-provisioner との共有のネットワークで受け、ピンのファイルを渡し、監査ログをホストに書く |
| `compose.fluent-bit.yaml` | ログを管理面の Fluent Bit に送るときに重ねる |

設定（環境変数）の一覧は[設計概要 §12](docs/design-overview.md)、手順は[運用ガイド](docs/operations.md)にあります。

## 開発

- Go 1.27.3 が要ります。`go test ./...` で単体・結合の試験、`CA_TEST_OPENSSL=1 go test ./...` で openssl による相互運用の試験も動きます。
- `scripts/check-guide.sh` は運用ガイドの管理モードの手順を compose で流して確かめます（CI のジョブと同じ）。
- 画面の CSS は `sh scripts/build-css.sh` で作ります（Tailwind CSS のスタンドアロン CLI と daisyUI を、版を固定して取得します）。

## ライセンス

[MIT](LICENSE)
