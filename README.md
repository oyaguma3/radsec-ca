# radsec-ca

[radsec-edge](https://github.com/oyaguma3/radsec-edge)（RadSec の AP を受けるエッジノード）のための独立した CA です。AP のクライアント証明書と、エッジのサーバー証明書を発行し、CRL を作って配ります。

- テナント（AP のグループ）ごとに自己署名のクライアントCA を持ち、テナントの間で証明書が通らないようにします。
- 証明書の CN・SAN・EKU・有効期限は、呼び出し側が渡す名前（テナント、AP、エッジ）から決まった規則で作ります。CSR から使うのは公開鍵だけです。
- CA の鍵は暗号化して保存します（AES-256-GCM。暗号化の鍵はファイルで渡す）。
- 運用者向けの Web GUI（Cloudflare Access）と、[eapaka-node-provisioner](https://github.com/oyaguma3/eapaka-node-provisioner) から呼ぶ管理API（mTLS）を持ちます。

## 状態

設計中です。実装はまだありません。

- 設計概要: [docs/design-overview.md](docs/design-overview.md)

## ライセンス

[MIT](LICENSE)
