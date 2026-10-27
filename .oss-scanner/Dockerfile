# Scanner image for https://github.com/justwaters/SIEMLite (main): a self-hosted SIEM in one Go binary.
#
# The audit runs offline, so this build fetches every Go module, builds the server, the log generator and a
# race-detector build of the server, and compiles every test. threat_model.md, next to this file, says how to start
# the server and where to look.

# go.mod asks for Go 1.27.x. This image carries gcc, which the race detector needs, plus git.
FROM golang:1.27-bookworm
ENV DEBIAN_FRONTEND=noninteractive
# curl to talk to a running server, openssl for its certificate, sqlite3 to look inside the database, netcat to send
# syslog by hand. Packages are fetched over HTTPS.
RUN sed -i 's|http://deb.debian.org|https://deb.debian.org|g' /etc/apt/sources.list.d/debian.sources \
    && apt-get update && apt-get install -y --no-install-recommends \
         ca-certificates curl openssl sqlite3 netcat-openbsd jq python3 \
    && rm -rf /var/lib/apt/lists/*

# scanner contract: the checkout lives inside the image, at /src
COPY . /src
WORKDIR /src

# Every module the server and its tests depend on (the audit has no network).
RUN go mod download

# The server and the log generator, built as the release is (static, no CGO), and a copy of the server with the race
# detector for finding data races while it runs. SQLite is pure Go (modernc.org/sqlite), so CGO is only for -race.
RUN mkdir -p /src/bin \
    && CGO_ENABLED=0 go build -trimpath -o /src/bin/siemlite . \
    && CGO_ENABLED=0 go build -trimpath -o /src/bin/loggen ./cmd/loggen \
    && CGO_ENABLED=1 go build -race -o /src/bin/siemlite-race .

# Compile every test, with and without -race, so a broken test fails the build. The fuzz targets and the security
# tests (go test ./api ./pkg/auth ./web -run '^TestSecurity') also need only the modules downloaded above.
RUN go vet ./... \
    && go test -run '^$' ./... \
    && CGO_ENABLED=1 go test -race -run '^$' ./...

# Run the tests so the log shows the image works, without letting a failure abort the build.
RUN (go test ./... || echo "WARNING: go test reported failures")
