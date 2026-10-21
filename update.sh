#!/bin/sh
# Update SIEMLite running with Docker Compose, saying which version it goes
# from and to:
#
#   ./update.sh            the newest release (or, when built from source, git pull and a rebuild)
#   ./update.sh v0.19.1    a particular release
#
# With a release image in .env (SIEMLITE_IMAGE=ghcr.io/justwaters/siemlite:<version>)
# it moves that line to the version wanted and pulls it; otherwise it builds
# the image from this folder. Then it restarts the stack and waits until
# SIEMLite reports healthy. The database and settings in the siemlite-data
# volume are kept, as with docker compose up -d.
set -eu
cd "$(dirname "$0")"

repo=ghcr.io/justwaters/siemlite
want=${1:-}
case "$want" in
'' | v[0-9]*) ;;
-h | --help)
	sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'
	exit 0
	;;
*)
	echo "Usage: ./update.sh [version], e.g. ./update.sh v0.19.1" >&2
	exit 2
	;;
esac

# The version running now, from SIEMLite's own log (this counts an update
# made from the System page), or else from the program in the image.
running() {
	v=$(docker compose logs --no-log-prefix siemlite 2>/dev/null | grep 'SIEMLite listening' | tail -n 1 |
		sed -n 's/.*version=\([^ ]*\).*/\1/p')
	if [ -z "$v" ]; then
		v=$(docker compose exec -T siemlite siemlite version 2>/dev/null | awk '{print $2}') || v=""
	fi
	echo "$v"
}

image_version() {
	docker run --rm "$1" version 2>/dev/null | awk '{print $2}'
}

newest_release() {
	url=https://api.github.com/repos/justwaters/SIEMLite/releases/latest
	if command -v curl >/dev/null 2>&1; then
		curl -fsS --max-time 15 "$url"
	elif command -v wget >/dev/null 2>&1; then
		wget -qO- --timeout=15 "$url"
	fi 2>/dev/null | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n 1
}

# older A B: is version A older than B? (v0.9.2 < v0.10 < v0.19 < v0.19.1)
older() {
	a=${1#v}
	b=${2#v}
	while [ -n "$a$b" ]; do
		x=${a%%.*}
		y=${b%%.*}
		[ "${x:-0}" -lt "${y:-0}" ] && return 0
		[ "${x:-0}" -gt "${y:-0}" ] && return 1
		case "$a" in *.*) a=${a#*.} ;; *) a="" ;; esac
		case "$b" in *.*) b=${b#*.} ;; *) b="" ;; esac
	done
	return 1
}

old=$(running)

pinned=""
if [ -f .env ]; then
	pinned=$(sed -n "s|^SIEMLITE_IMAGE=$repo:\(v[0-9][^ ]*\)\$|\1|p" .env | tail -n 1)
fi

if [ -n "$pinned" ]; then
	if [ -z "$want" ]; then
		want=$(newest_release)
		if [ -z "$want" ]; then
			echo "Couldn't ask GitHub for the newest release; staying on $pinned. Name a version to change it: ./update.sh v0.19.1" >&2
			want=$pinned
		fi
	fi
	if [ "$want" != "$pinned" ]; then
		sed -i.bak "s|^SIEMLITE_IMAGE=$repo:.*\$|SIEMLITE_IMAGE=$repo:$want|" .env && rm -f .env.bak
	fi
	echo "Downloading SIEMLite $want..."
	docker compose pull --quiet
	image=$repo:$want
else
	if [ -n "$want" ]; then
		echo "This SIEMLite is built from this folder, so it can't switch to $want." >&2
		echo "Run git pull (or git checkout $want) first, or set SIEMLITE_IMAGE=$repo:$want in .env to use a release." >&2
		exit 2
	fi
	if [ -d .git ] && command -v git >/dev/null 2>&1; then
		echo "Getting the newest SIEMLite source (git pull)..."
		git pull --ff-only --quiet || echo "git pull didn't apply (local changes, or another branch); building what's here." >&2
	fi
	echo "Building SIEMLite from this folder..."
	docker compose build --quiet siemlite
	image=$(docker compose config --images siemlite | head -n 1)
fi

new=$(image_version "$image")
case "$old" in
"") echo "Starting SIEMLite $new" ;;
"$new") echo "SIEMLite $new is already running; restarting with any changed settings" ;;
*)
	if older "$new" "$old"; then
		echo "Going back: SIEMLite $old -> $new"
		echo "A newer version may have changed the database in ways $new can't read. Restore a backup made on $new if it doesn't start." >&2
		if [ -t 0 ]; then
			printf "Go back to %s? [y/N] " "$new"
			read -r yes
			case "$yes" in y | Y | yes) ;; *)
				if [ -n "$pinned" ]; then
					sed -i.bak "s|^SIEMLITE_IMAGE=$repo:.*\$|SIEMLITE_IMAGE=$repo:$pinned|" .env && rm -f .env.bak
				fi
				echo "Nothing changed: still $old." >&2
				exit 1
				;;
			esac
		fi
	else
		echo "Updating SIEMLite $old -> $new"
	fi
	;;
esac

docker compose up -d --quiet-pull

# Wait for SIEMLite to say it is healthy (its health check runs every 30s).
id=$(docker compose ps -q siemlite)
i=0
while [ $i -lt 30 ]; do
	status=$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$id" 2>/dev/null || echo gone)
	case "$status" in
	healthy | running)
		echo "SIEMLite $(running) is up."
		exit 0
		;;
	unhealthy | exited | dead | gone)
		break
		;;
	esac
	sleep 3
	i=$((i + 1))
done
echo "SIEMLite hasn't reported healthy yet ($status). See what it says with: docker compose logs --tail 50 siemlite" >&2
exit 1
