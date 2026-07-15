#!/bin/sh
set -eu

INSTALL_NAME=herdr-port-forward
RELEASE_BASE_URL=https://github.com/Whamp/herdr/releases/download/remote-link-externalization-test
REMOTE_TARGET=
DRY_RUN=false
TEMP_DIR=

cleanup() {
    if [ -n "$TEMP_DIR" ] && [ -d "$TEMP_DIR" ]; then
        rm -rf "$TEMP_DIR"
    fi
}
trap cleanup EXIT HUP INT TERM

usage() {
    cat <<'EOF'
Install the remote-link test build alongside stable Herdr.

Usage:
  install-port-forward-test.sh [--remote <ssh-target>] [--dry-run]
  install-port-forward-test.sh --help

Options:
  --remote <ssh-target>  Also install herdr-port-forward on any SSH target.
  --dry-run              Print the local and remote installation plan only.
  --help                 Show this help.
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --remote)
            if [ "$#" -lt 2 ] || [ -z "$2" ]; then
                echo "error: --remote requires an SSH target" >&2
                exit 2
            fi
            case "$2" in
                -*)
                    echo "error: SSH target must not start with '-'" >&2
                    exit 2
                    ;;
            esac
            REMOTE_TARGET=$2
            shift 2
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        *)
            echo "error: unknown argument: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

platform_key() {
    os=$1
    arch=$2
    case "$os:$arch" in
        Linux:x86_64) printf '%s\n' linux-x86_64 ;;
        Linux:aarch64|Linux:arm64) printf '%s\n' linux-aarch64 ;;
        Darwin:x86_64) printf '%s\n' macos-x86_64 ;;
        Darwin:aarch64|Darwin:arm64) printf '%s\n' macos-aarch64 ;;
        *)
            echo "error: unsupported platform: $os $arch" >&2
            return 1
            ;;
    esac
}

local_platform=$(platform_key "$(uname -s)" "$(uname -m)")
local_artifact="$INSTALL_NAME-$local_platform"

if [ "$DRY_RUN" = true ]; then
    printf 'Would install %s to %s/.local/bin/%s\n' "$local_artifact" "$HOME" "$INSTALL_NAME"
    if [ -n "$REMOTE_TARGET" ]; then
        remote_platform_output=$(ssh "$REMOTE_TARGET" 'uname -s; uname -m')
        remote_os=$(printf '%s\n' "$remote_platform_output" | sed -n '1p')
        remote_arch=$(printf '%s\n' "$remote_platform_output" | sed -n '2p')
        remote_platform=$(platform_key "$remote_os" "$remote_arch")
        printf 'Would install %s-%s on SSH target %s\n' \
            "$INSTALL_NAME" "$remote_platform" "$REMOTE_TARGET"
    fi
    exit 0
fi

TEMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/herdr-port-forward-install.XXXXXX")

verify_checksum() {
    checksum_file=$1
    if command -v sha256sum >/dev/null 2>&1; then
        (cd "$TEMP_DIR" && sha256sum -c "$(basename "$checksum_file")")
    elif command -v shasum >/dev/null 2>&1; then
        (cd "$TEMP_DIR" && shasum -a 256 -c "$(basename "$checksum_file")")
    else
        echo "error: sha256sum or shasum is required" >&2
        return 1
    fi
}

download_artifact() {
    platform=$1
    artifact_name="$INSTALL_NAME-$platform"
    artifact_path="$TEMP_DIR/$artifact_name"
    checksum_path="$artifact_path.sha256"
    curl -fsSL --retry 3 -o "$artifact_path" "$RELEASE_BASE_URL/$artifact_name"
    curl -fsSL --retry 3 -o "$checksum_path" "$RELEASE_BASE_URL/$artifact_name.sha256"
    verify_checksum "$checksum_path" >&2
    chmod 755 "$artifact_path"
    printf '%s\n' "$artifact_path"
}

local_source=$(download_artifact "$local_platform")
local_status=$("$local_source" status client --json)
if ! printf '%s\n' "$local_status" | grep -q '"protocol":17'; then
    echo "error: downloaded build does not report protocol 17" >&2
    exit 1
fi

local_dir="$HOME/.local/bin"
local_destination="$local_dir/$INSTALL_NAME"
mkdir -p "$local_dir"
install -m 755 "$local_source" "$local_destination.tmp"
mv "$local_destination.tmp" "$local_destination"
printf 'Installed %s\n' "$local_destination"
printf '%s\n' "$local_status"

if [ -n "$REMOTE_TARGET" ]; then
    remote_platform_output=$(ssh "$REMOTE_TARGET" 'uname -s; uname -m')
    remote_os=$(printf '%s\n' "$remote_platform_output" | sed -n '1p')
    remote_arch=$(printf '%s\n' "$remote_platform_output" | sed -n '2p')
    remote_platform=$(platform_key "$remote_os" "$remote_arch")
    remote_source=$(download_artifact "$remote_platform")

    cat "$remote_source" | ssh "$REMOTE_TARGET" 'set -eu
        dir="$HOME/.local/bin"
        destination="$dir/herdr-port-forward"
        temporary="$destination.tmp.$$"
        trap '\''rm -f "$temporary"'\'' EXIT HUP INT TERM
        mkdir -p "$dir"
        cat > "$temporary"
        chmod 755 "$temporary"
        mv "$temporary" "$destination"'

    remote_status=$(ssh "$REMOTE_TARGET" '"$HOME/.local/bin/herdr-port-forward" status client --json')
    if ! printf '%s\n' "$remote_status" | grep -q '"protocol":17'; then
        echo "error: installed remote build does not report protocol 17" >&2
        exit 1
    fi
    printf 'Installed remote ~/.local/bin/%s on %s\n' "$INSTALL_NAME" "$REMOTE_TARGET"
    printf '%s\n' "$remote_status"
    printf '\nNext: %s --remote %s --session port-forward-test\n' \
        "$local_destination" "$REMOTE_TARGET"
else
    printf '\nTo install a remote peer too, rerun with --remote <ssh-target>.\n'
fi
