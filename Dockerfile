# syntax=docker/dockerfile:1

FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/tailscale-chat ./

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app
COPY --from=build /out/tailscale-chat /app/tailscale-chat
ENV TSNET_FORCE_LOGIN_INTERACTIVE=false
EXPOSE 443
# Run state dir inside /app (writable for nonroot in this image is /tmp; point -state-dir there).
ENTRYPOINT ["/app/tailscale-chat", "-funnel", "-state-dir", "/tmp/tsnet-state", "-db", "/tmp/chat.jsonl"]
