#!/bin/sh
set -eu

if [ "$#" -eq 0 ]; then
	set -- serve
fi

case "$1" in
	-*)
		set -- serve "$@"
		;;
esac

start_anisette=0
if [ "$1" = "serve" ] || [ "$1" = "debug" ]; then
	start_anisette=1
	for arg in "$@"; do
		case "$arg" in
			-list|--list|-h|--help|-anisette-server|--anisette-server|-anisette-server=*|--anisette-server=*)
				start_anisette=0
				break
				;;
		esac
	done
fi

if [ "$start_anisette" -eq 1 ]; then
	/opt/anisette-v3-server \
		-n 127.0.0.1 \
		-p 6969 \
		-a /opt/anisette-v3 &
	anisette_pid=$!

	i=0
	while ! curl -fsS http://127.0.0.1:6969/v3/client_info >/dev/null 2>&1; do
		if ! kill -0 "$anisette_pid" 2>/dev/null; then
			echo "iprd: bundled anisette-v3-server exited unexpectedly" >&2
			exit 1
		fi
		i=$((i + 1))
		if [ "$i" -ge 120 ]; then
			echo "iprd: timed out waiting for bundled anisette-v3-server" >&2
			kill "$anisette_pid" 2>/dev/null || true
			exit 1
		fi
		sleep 0.5
	done

	/usr/local/bin/iprd "$@" &
	iprd_pid=$!
	trap 'kill -TERM "$iprd_pid" "$anisette_pid" 2>/dev/null || true' INT TERM
	set +e
	wait "$iprd_pid"
	status=$?
	set -e
	kill "$anisette_pid" 2>/dev/null || true
	wait "$anisette_pid" 2>/dev/null || true
	exit "$status"
fi

exec /usr/local/bin/iprd "$@"
