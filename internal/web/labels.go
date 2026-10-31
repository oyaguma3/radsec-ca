package web

import "github.com/oyaguma3/radsec-ca/internal/db"

func profileLabel(p string) string {
	switch p {
	case db.ProfileAPClient:
		return "AP（ap-client）"
	case db.ProfileGroupClient:
		return "グループ（group-client）"
	case db.ProfileProbeClient:
		return "ヘルスチェック（probe-client）"
	case db.ProfileTenantServer:
		return "サーバー（tenant-server）"
	}
	return p
}

// crlSourceLabel は CRL の取得先の名前（§19.3）。
func crlSourceLabel(s string) string {
	switch s {
	case db.CRLSourceIssued:
		return "本CA が作る"
	case db.CRLSourceURL:
		return "URL から取る"
	case db.CRLSourceMeraki:
		return "Meraki の Dashboard API から取る"
	case db.CRLSourceUpload:
		return "アップロードを受ける"
	case db.CRLSourceNone:
		return "なし（業者の AP の失効は効きません）"
	}
	return s
}

func statusLabel(s string) string {
	switch s {
	case "valid":
		return "有効"
	case "revoked":
		return "失効"
	case "expired":
		return "期限切れ"
	}
	return s
}

// reasonLabels は失効の理由の名前（§7.1）。
var reasonLabels = []struct{ Value, Label string }{
	{"unspecified", "unspecified（指定なし）"},
	{"keyCompromise", "keyCompromise（鍵の漏えい）"},
	{"superseded", "superseded（更新した）"},
	{"cessationOfOperation", "cessationOfOperation（AP やテナントをやめた）"},
}

var auditLabels = map[string]string{
	"ca.create":            "CA の作成",
	"ca.disable":           "CA の停止",
	"ca.register":          "持ち込みの CA の登録",
	"ca.crl.upload":        "CRL のアップロード",
	"ca.crl.refresh":       "CRL の取り直し",
	"ca.crl_source.change": "CRL の取得先の変更",
	"server-cert.replace":  "サーバー証明書の作り直し",
	"cert.issue":           "発行",
	"cert.revoke":          "失効",
	"user.create":          "利用者の追加",
	"user.update":          "利用者の変更",
	"kek.rotate":           "KEK の入れ替え",
	"backup":               "バックアップ",
}

func auditLabel(s string) string {
	if l, ok := auditLabels[s]; ok {
		return l
	}
	return s
}
