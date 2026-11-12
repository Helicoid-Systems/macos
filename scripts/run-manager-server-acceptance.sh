#!/usr/bin/env bash
#
# Disposable macOS acceptance for the real Manager -> LocalServerInstallClient
# lifecycle.
#
# NEVER run this on a machine that matters. This script is intentionally
# restricted to ephemeral GitHub-hosted macOS runners on the exact trusted
# branch. No protected environment, OIDC trust, or guarded runner is assumed:
# a compromised workflow, token, or runner can defeat these checks. The only
# containment is that the runner is destroyed after the job.
#
# Authorization model:
#   * The acceptance suite proves every fixed host resource absent using root
#     lstat, explicit dscl record-not-found, and explicit launchd not-found.
#   * Only after those checks does the suite write a run-bound marker containing
#     repository, exact branch, github.run_id, github.run_attempt, and a
#     per-run nonce.
#   * Cleanup is authorized only by that validated marker content. A missing,
#     forged, stale, or malformed marker authorizes no deletion.
#   * Cleanup never treats an unknown command result as absence. Unknown state
#     refuses cleanup.
#   * The `_helicoid` identity is deleted only after a valid install receipt
#     proves the product, account/group, and matching UID/GID. Otherwise it is
#     preserved and the run fails.
#
# Usage:
#   run-manager-server-acceptance.sh client|model|cleanup
#
# `cleanup` is used by the workflow's always-run fallback step. It performs only
# marker-authorized cleanup and reads no acceptance artifacts.
#
# Environment (set by the workflow):
#   HELICOID_ACCEPTANCE_MANAGER_APP  absolute packaged development Manager app
#   HELICOID_MACOS_DEV_TRUST_KEY     64-hex build-pinned development key
#   HELICOID_MANAGER_ACCEPTANCE_NONCE      32 lowercase hex characters
#   HELICOID_MANAGER_ACCEPTANCE_MARKER     exact run-bound marker path
#   RUNNER_TEMP, GITHUB_RUN_ID, GITHUB_RUN_ATTEMPT, GITHUB_REF

set -euo pipefail

mode=${1:-}
case "$mode" in
client | model | cleanup) ;;
*)
	printf 'Usage: %s client|model|cleanup\n' "${0##*/}" >&2
	exit 2
	;;
esac

die() {
	printf 'Error: %s\n' "$1" >&2
	exit 1
}

[[ "$(uname -s)" == "Darwin" ]] || die "this acceptance runs only on macOS"
[[ "$(id -u)" -ne 0 ]] || die "run as the normal runner user, not root"
[[ "${GITHUB_ACTIONS:-}" == "true" ]] || die "GitHub Actions is required"
[[ "${RUNNER_ENVIRONMENT:-}" == "github-hosted" ]] || die "a GitHub-hosted runner is required"
[[ "${GITHUB_REPOSITORY:-}" == "Helicoid-Systems/macos" ]] || die "only Helicoid-Systems/macos may run this acceptance"
[[ "${GITHUB_REF:-}" == "refs/heads/codex/macos-native-combined" ]] \
	|| die "only refs/heads/codex/macos-native-combined may run this acceptance"
[[ -n "${GITHUB_RUN_ID:-}" && -n "${GITHUB_RUN_ATTEMPT:-}" ]] \
	|| die "github.run_id and github.run_attempt are required"
[[ -n "${RUNNER_TEMP:-}" && -d "$RUNNER_TEMP" ]] || die "RUNNER_TEMP is required"
nonce=${HELICOID_MANAGER_ACCEPTANCE_NONCE:-}
marker=${HELICOID_MANAGER_ACCEPTANCE_MARKER:-}
[[ "$nonce" =~ ^[0-9a-f]{32}$ ]] || die "the acceptance nonce is missing or malformed"
expected_marker="$RUNNER_TEMP/helicoid-manager-acceptance-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}-${nonce}.clean"
[[ "$marker" == "$expected_marker" ]] || die "the marker path is not bound to this run and nonce"
[[ -x /usr/bin/python3 ]] || die "/usr/bin/python3 is required for authoritative host state checks"
/usr/bin/sudo -n /usr/bin/true >/dev/null 2>&1 || die "passwordless sudo is required on the disposable runner"

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
cd -- "$repo_root"

work=""
acceptance_proof=""
if [ "$mode" != "cleanup" ]; then
	[[ -n "${HELICOID_ACCEPTANCE_MANAGER_APP:-}" ]] \
		|| die "HELICOID_ACCEPTANCE_MANAGER_APP is required"
	[[ -n "${HELICOID_MACOS_DEV_TRUST_KEY:-}" ]] \
		|| die "HELICOID_MACOS_DEV_TRUST_KEY is required"
	[[ "$HELICOID_MACOS_DEV_TRUST_KEY" =~ ^[0-9a-fA-F]{64}$ ]] \
		|| die "HELICOID_MACOS_DEV_TRUST_KEY is not 64 hex characters"
	[[ -d "$HELICOID_ACCEPTANCE_MANAGER_APP" ]] \
		|| die "the packaged Manager app does not exist"
	work=$(/usr/bin/mktemp -d "$RUNNER_TEMP/helicoid-manager-acceptance-work.XXXXXXXX") \
		|| die "cannot create the acceptance work directory"
	acceptance_proof="$work/acceptance-passed"
fi

label=com.helicoid.server
plist=/Library/LaunchDaemons/com.helicoid.server.plist
product_root="/Library/Application Support/Helicoid"
state_dir="/Library/Application Support/Helicoid-Installer"
lock_file="/Library/Application Support/Helicoid-Installer.lock"
payload_root="/Library/Application Support/Helicoid-Installer-Payload"
# The macOS plan never creates this configured backup directory. Refuse to
# adopt it at startup and never delete it during cleanup.
backup_path="/Library/Application Support/Helicoid-Backups"
tls_root=/etc/helicoid
receipt_path="$product_root/Configuration/install-receipt.json"

clean_state_paths=(
	"$plist"
	"$product_root"
	"$state_dir"
	"$lock_file"
	"$payload_root"
	"$backup_path"
	"$tls_root"
)

deletable_paths=(
	"$plist"
	"$product_root"
	"$state_dir"
	"$lock_file"
	"$payload_root"
	"$tls_root"
)

# Root lstat kind. Output is one of: absent, file, dir, symlink, other, unknown.
# Unknown is never treated as absence.
root_path_kind() {
	local path="$1" output status
	if output=$(/usr/bin/sudo -n /usr/bin/python3 - "$path" 2>/dev/null <<'PY'
import os
import stat
import sys

try:
    info = os.lstat(sys.argv[1])
except FileNotFoundError:
    print("absent")
    raise SystemExit(0)
except OSError:
    print("unknown")
    raise SystemExit(0)

mode = info.st_mode
if stat.S_ISREG(mode):
    print("file")
elif stat.S_ISDIR(mode):
    print("dir")
elif stat.S_ISLNK(mode):
    print("symlink")
else:
    print("other")
PY
	); then
		status=0
	else
		status=$?
	fi
	if [ "$status" -ne 0 ]; then
		printf 'unknown'
		return 0
	fi
	case "$output" in
	absent | file | dir | symlink | other) printf '%s' "$output" ;;
	*) printf 'unknown' ;;
	esac
}

# Explicit dscl state. Only status 56 with eDSRecordNotFound is absence.
record_state() {
	local record="$1" output status
	if output=$(/usr/bin/sudo -n /usr/bin/dscl . -read "/$record" 2>&1); then
		status=0
	else
		status=$?
	fi
	if [ "$status" -eq 0 ]; then
		printf 'present'
		return 0
	fi
	if [ "$status" -eq 56 ] \
		&& printf '%s' "$output" | /usr/bin/grep -Fq 'eDSRecordNotFound'; then
		printf 'absent'
		return 0
	fi
	printf 'unknown'
}

# Explicit launchd state. Only the authoritative not-found text is absence.
service_state() {
	local output status
	if output=$(/usr/bin/sudo -n /bin/launchctl print "system/$label" 2>&1); then
		status=0
	else
		status=$?
	fi
	if [ "$status" -eq 0 ]; then
		printf 'present'
		return 0
	fi
	if printf '%s' "$output" | /usr/bin/grep -Fq 'Could not find service'; then
		printf 'absent'
		return 0
	fi
	printf 'unknown'
}

marker_expected() {
	printf '%s\n%s\n%s\n%s\n%s\n%s' \
		'helicoid-manager-acceptance-v1' \
		'repository=Helicoid-Systems/macos' \
		'branch=codex/macos-native-combined' \
		"run_id=$GITHUB_RUN_ID" \
		"run_attempt=$GITHUB_RUN_ATTEMPT" \
		"nonce=$nonce"
}

# 0 = valid, 1 = absent, 2 = present but invalid/unknown.
validate_marker() {
	local state actual meta cat_status stat_status
	state=$(root_path_kind "$marker")
	case "$state" in
	absent) return 1 ;;
	file) ;;
	*) return 2 ;;
	esac
	if actual=$(/bin/cat "$marker" 2>/dev/null); then
		cat_status=0
	else
		cat_status=$?
	fi
	if meta=$(/usr/bin/stat -f '%u:%Lp' "$marker" 2>/dev/null); then
		stat_status=0
	else
		stat_status=$?
	fi
	[ "$cat_status" -eq 0 ] && [ "$stat_status" -eq 0 ] || return 2
	[ "$actual" = "$(marker_expected)" ] || return 2
	[ "$meta" = "$(/usr/bin/id -u):600" ] || return 2
	return 0
}

identity_created_by_run() {
	local state receipt uid gid meta
	local meta_status receipt_status uid_status gid_status
	state=$(root_path_kind "$receipt_path")
	[ "$state" = file ] || return 1
	if meta=$(/usr/bin/sudo -n /usr/bin/stat -f '%u:%Lp' "$receipt_path" 2>/dev/null); then
		meta_status=0
	else
		meta_status=$?
	fi
	if receipt=$(/usr/bin/sudo -n /bin/cat "$receipt_path" 2>/dev/null); then
		receipt_status=0
	else
		receipt_status=$?
	fi
	if uid=$(/usr/bin/id -u _helicoid 2>/dev/null); then
		uid_status=0
	else
		uid_status=$?
	fi
	if gid=$(/usr/bin/id -g _helicoid 2>/dev/null); then
		gid_status=0
	else
		gid_status=$?
	fi
	[ "$meta_status" -eq 0 ] && [ "$meta" = "0:644" ] || return 1
	[ "$receipt_status" -eq 0 ] && [ "$uid_status" -eq 0 ] && [ "$gid_status" -eq 0 ] \
		|| return 1
	/usr/bin/python3 - "$uid" "$gid" "$receipt" <<'PY'
import json
import sys

try:
    receipt = json.loads(sys.argv[3])
except Exception:
    raise SystemExit(1)

ok = (
    receipt.get("product") == "hs-server"
    and receipt.get("service_account") == "_helicoid"
    and receipt.get("service_group") == "_helicoid"
    and str(receipt.get("unique_id")) == sys.argv[1]
    and str(receipt.get("primary_group_id")) == sys.argv[2]
)
raise SystemExit(0 if ok else 1)
PY
}

require_clean_state() {
	local path state
	for path in "${clean_state_paths[@]}"; do
		state=$(root_path_kind "$path")
		[ "$state" = absent ] \
			|| die "path is not proven absent: $path ($state)"
	done
	state=$(record_state Users/_helicoid)
	[ "$state" = absent ] || die "user _helicoid is not proven absent ($state)"
	state=$(record_state Groups/_helicoid)
	[ "$state" = absent ] || die "group _helicoid is not proven absent ($state)"
	state=$(service_state)
	[ "$state" = absent ] || die "launchd job $label is not proven absent ($state)"
	state=$(root_path_kind "$marker")
	[ "$state" = absent ] || die "the run-bound marker path is not absent ($state)"
}

cleanup() {
	set +e
	local cleanup_failed=0 identity_proof_failed=0 destructive_ok=1
	local marker_status state identity_ok=0 identity_proof_verified=0
	local user_state group_state
	local path output status

	validate_marker
	marker_status=$?

	if [ "$marker_status" -eq 1 ]; then
		# No marker authorizes no deletion. Refuse if any resource is present or
		# its state is unknown; otherwise the clean state is already intact.
		for path in "${clean_state_paths[@]}"; do
			state=$(root_path_kind "$path")
			if [ "$state" != absent ]; then
				printf 'Error: resource present or unknown without a valid marker: %s (%s)\n' \
					"$path" "$state" >&2
				cleanup_failed=1
			fi
		done
		state=$(record_state Users/_helicoid)
		if [ "$state" != absent ]; then
			printf 'Error: _helicoid user present or unknown without a valid marker (%s)\n' \
				"$state" >&2
			cleanup_failed=1
		fi
		state=$(record_state Groups/_helicoid)
		if [ "$state" != absent ]; then
			printf 'Error: _helicoid group present or unknown without a valid marker (%s)\n' \
				"$state" >&2
			cleanup_failed=1
		fi
		state=$(service_state)
		if [ "$state" != absent ]; then
			printf 'Error: launchd job present or unknown without a valid marker (%s)\n' \
				"$state" >&2
			cleanup_failed=1
		fi
	elif [ "$marker_status" -ne 0 ]; then
		printf 'Error: the run-bound marker is present but invalid; refusing all cleanup\n' >&2
		if [ -n "${work:-}" ] && [ -d "$work" ]; then
			/bin/rm -rf -- "$work" || :
		fi
		return 1
	fi

	if [ "$marker_status" -eq 0 ] && [ "$cleanup_failed" -eq 0 ]; then
		# Capture identity authorization before deleting the receipt's parent.
		user_state=$(record_state Users/_helicoid)
		group_state=$(record_state Groups/_helicoid)
		if [ "$user_state" = absent ] && [ "$group_state" = absent ]; then
			identity_ok=1
		elif [ "$user_state" = unknown ] || [ "$group_state" = unknown ]; then
			printf 'Error: _helicoid identity state is unknown; preserving identity\n' >&2
			identity_proof_failed=1
			destructive_ok=0
		elif identity_created_by_run; then
			identity_ok=1
			identity_proof_verified=1
		else
			printf 'Error: cannot prove _helicoid was created by this run; preserving identity\n' >&2
			identity_proof_failed=1
			destructive_ok=0
		fi

		state=$(service_state)
		case "$state" in
		present)
			local bootout_status=0
			/usr/bin/sudo -n /bin/launchctl bootout "system/$label" >/dev/null 2>&1 \
				|| bootout_status=$?
			for _ in {1..20}; do
				state=$(service_state)
				[ "$state" = present ] || break
				/bin/sleep 0.5
			done
			if [ "$state" != absent ]; then
				printf 'Error: launchd job did not stop cleanly (%s, bootout status %s)\n' \
					"$state" "$bootout_status" >&2
				destructive_ok=0
				cleanup_failed=1
			fi
			;;
		absent) ;;
		*)
			printf 'Error: launchd state is unknown; refusing destructive cleanup (%s)\n' \
				"$state" >&2
			destructive_ok=0
			cleanup_failed=1
			;;
		esac

		if [ "$destructive_ok" -eq 1 ]; then
			for path in "${deletable_paths[@]}"; do
				state=$(root_path_kind "$path")
				case "$state" in
				absent) ;;
				file | dir | symlink | other)
					/usr/bin/sudo -n /bin/rm -rf -- "$path" || cleanup_failed=1
					;;
				*)
					printf 'Error: refusing to delete %s because its state is unknown\n' \
						"$path" >&2
					cleanup_failed=1
					;;
				esac
			done
		fi

		if [ "$destructive_ok" -eq 1 ]; then
			for path in "${clean_state_paths[@]}"; do
				state=$(root_path_kind "$path")
				if [ "$state" != absent ]; then
					printf 'Error: leftover or unknown resource after cleanup: %s (%s)\n' \
						"$path" "$state" >&2
					cleanup_failed=1
				fi
			done
			state=$(service_state)
			if [ "$state" != absent ]; then
				printf 'Error: launchd job remains after cleanup (%s)\n' "$state" >&2
				cleanup_failed=1
			fi
		fi

		if [ "$identity_proof_failed" -ne 0 ]; then
			cleanup_failed=1
		fi

		if [ "$cleanup_failed" -eq 0 ] && [ "$identity_ok" -eq 1 ]; then
			user_state=$(record_state Users/_helicoid)
			if [ "$user_state" = present ]; then
				if [ "$identity_proof_verified" -eq 1 ]; then
					/usr/bin/sudo -n /usr/bin/dscl . -delete /Users/_helicoid \
						|| cleanup_failed=1
				else
					printf 'Error: _helicoid user appeared without a receipt proof; preserving identity\n' >&2
					cleanup_failed=1
				fi
			elif [ "$user_state" = unknown ]; then
				cleanup_failed=1
			fi
			user_state=$(record_state Users/_helicoid)
			if [ "$user_state" != absent ]; then
				printf 'Error: _helicoid user remains or is unknown; preserving group\n' >&2
				cleanup_failed=1
			else
				group_state=$(record_state Groups/_helicoid)
				if [ "$group_state" = present ]; then
					if [ "$identity_proof_verified" -eq 1 ]; then
						/usr/bin/sudo -n /usr/bin/dscl . -delete /Groups/_helicoid \
							|| cleanup_failed=1
					else
						printf 'Error: _helicoid group appeared without a receipt proof; preserving identity\n' >&2
						cleanup_failed=1
					fi
				elif [ "$group_state" = unknown ]; then
					cleanup_failed=1
				fi
				group_state=$(record_state Groups/_helicoid)
				if [ "$group_state" != absent ]; then
					printf 'Error: _helicoid group remains or is unknown\n' >&2
					cleanup_failed=1
				fi
			fi
			# Cache flush is best effort; the dscl checks above and below are
			# the authoritative identity proof.
			/usr/bin/sudo -n /usr/bin/dscacheutil -flushcache >/dev/null 2>&1 || :
		fi
	fi

	# Final proof: no unknown state is allowed to pass as clean.
	[ "$cleanup_failed" -ne 0 ] || {
		for path in "${clean_state_paths[@]}"; do
			state=$(root_path_kind "$path")
			[ "$state" = absent ] || cleanup_failed=1
		done
		state=$(record_state Users/_helicoid)
		[ "$state" = absent ] || cleanup_failed=1
		state=$(record_state Groups/_helicoid)
		[ "$state" = absent ] || cleanup_failed=1
		state=$(service_state)
		[ "$state" = absent ] || cleanup_failed=1
	}

	if [ "$cleanup_failed" -eq 0 ]; then
		if ! /bin/rm -f -- "$marker"; then
			printf 'Error: could not remove the run-bound marker\n' >&2
			cleanup_failed=1
		fi
	else
		printf 'Error: cleanup did not fully verify; the run-bound marker is preserved\n' >&2
	fi
	if [ -n "${work:-}" ] && [ -d "$work" ]; then
		/bin/rm -rf -- "$work" || :
	fi
	return "$cleanup_failed"
}

if [ "$mode" = cleanup ]; then
	set +e
	cleanup
	status=$?
	set -e
	exit "$status"
fi

trap 'rc=$?; set +e; cleanup; crc=$?; if [ "$rc" -eq 0 ] && [ "$crc" -ne 0 ]; then exit 1; fi; exit "$rc"' EXIT
trap 'exit 128' HUP INT TERM

phase() {
	printf '\n== %s ==\n' "$1"
}

phase "assert disposable clean state (read-only)"
require_clean_state

phase "verify the packaged development Manager payload"
"$repo_root/scripts/hs-server-development-bundle.sh" verify \
	--app "$HELICOID_ACCEPTANCE_MANAGER_APP"

phase "run Manager acceptance suite ($mode)"
export HELICOID_MANAGER_ACCEPTANCE=1
export HELICOID_MANAGER_ACCEPTANCE_MARKER="$marker"
export HELICOID_MANAGER_ACCEPTANCE_PROOF="$acceptance_proof"
export HELICOID_ACCEPTANCE_MANAGER_APP
export HELICOID_MACOS_DEV_TRUST_KEY

case "$mode" in
client) filter=ManagerServerInstallAcceptanceTests ;;
model) filter=ManagerServerModelAcceptanceTests ;;
esac

xcrun swift test \
	--package-path "$repo_root" \
	--scratch-path "$repo_root/.build" \
	--filter "$filter"

# A filter typo or a silently skipped suite must not count as acceptance.
[ -s "$acceptance_proof" ] \
	|| die "the acceptance suite did not write its completion proof"
[ "$(/bin/cat "$acceptance_proof")" = "$mode" ] \
	|| die "the acceptance proof does not match mode $mode"

printf '\nacceptance mode %s passed\n' "$mode"
