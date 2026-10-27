# radsec-ca のイメージ（設計概要 §4）。
FROM golang:1.27.3 AS build
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# 画面の CSS を作る（Tailwind CSS のスタンドアロン CLI と daisyUI。版とチェックサムは scripts/build-css.sh で固定）。
RUN --mount=type=cache,target=/root/.cache/ca-css CA_CSS_CACHE=/root/.cache/ca-css sh scripts/build-css.sh
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/radsec-ca ./cmd/radsec-ca \
 && mkdir -p /out/data

FROM gcr.io/distroless/static-debian13:nonroot
COPY --from=build /out/radsec-ca /radsec-ca
# DB と管理API のサーバー証明書を置くディレクトリ。compose の名前つきボリュームをここにマウントすると、空のボリュームは
# この所有者（distroless の nonroot、65532）と権限を引き継ぐ。
COPY --from=build --chown=65532:65532 --chmod=0700 /out/data /data
ENTRYPOINT ["/radsec-ca"]
CMD ["serve"]
