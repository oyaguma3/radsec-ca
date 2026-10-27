# radsec-ca

[radsec-edge](https://github.com/oyaguma3/radsec-edge)（RadSec の AP を受けるエッジノード）のための独立した CA です。AP のクライアント証明書と、エッジのサーバー証明書を発行し、CRL を作って配ります。

- テナント（AP のグループ）ごとに自己署名のクライアントCA を持ち、テナントの間で証明書が通らないようにします。
- 証明書の CN・SAN・EKU・有効期限は、呼び出し側が渡す名前（テナント、AP、エッジ）から決まった規則で作ります。CSR から使うのは公開鍵だけです。
- CA の鍵は暗号化して保存します（AES-256-GCM。暗号化の鍵はファイルで渡す）。
- 運用者向けの Web GUI（Cloudflare Access）と、[eapaka-node-provisioner](https://github.com/oyaguma3/eapaka-node-provisioner) から呼ぶ管理API（mTLS）を持ちます。

## 状態

開発中です。段階 2（CA の管理、署名、失効と CRL、配布の口、管理API、画面）を作りました。radsec-edge とつないだ通しの確かめ（段階 3）はこれからです。

- 設計概要: [docs/design-overview.md](docs/design-overview.md)
- 管理API: [docs/openapi/ca-api.yaml](docs/openapi/ca-api.yaml)
- 運用ガイド（下書き）: [docs/operations.md](docs/operations.md)

## 口

| 口 | ポート | 内容 |
|---|---|---|
| 画面 | 8448（HTTP） | 運用者向け（Cloudflare Access）。CA と証明書の一覧、署名（単独モード）、失効、利用者（admin / viewer）、監査ログ |
| 管理API | 9448（HTTPS、mTLS） | provisioner から（管理モード）。CA の作成と停止、発行、失効、CRL |
| 配布 | 8449（HTTP） | エッジから。`GET /ca/{caId}.pem`、`GET /crl/{caId}.pem`（`ETag` つき） |

CA の ID はサーバーCA が `server`、テナントのクライアントCA が `tenant.<slug>` です。プロファイルは `ap-client`（AP）、`probe-client`（エッジのヘルスチェック）、`tenant-server`（エッジのサーバー証明書）の 3 つです。

## 開発

- Go 1.27.3 が要ります。`go test ./...` で単体・結合の試験、`CA_TEST_OPENSSL=1 go test ./...` で openssl による相互運用の試験も動きます。
- 画面の CSS は `sh scripts/build-css.sh` で作ります（Tailwind CSS のスタンドアロン CLI と daisyUI を、版を固定して取得します）。

## ライセンス

[MIT](LICENSE)
