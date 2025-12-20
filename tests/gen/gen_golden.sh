#!/usr/bin/env bash
set -eu

if git rev-parse --git-dir > /dev/null 2>&1; then
    PROJECT_ROOT="$(git rev-parse --show-toplevel)"
else
    PROJECT_ROOT="$(dirname "$(cargo locate-project --workspace --message-format plain)")"
fi

if [[ -z $PROJECT_ROOT ]]; then
    echo "No project root found." >&2
    exit 1
fi

declare tpl="${PROJECT_ROOT}/template.j2"
declare cfg="${PROJECT_ROOT}/tests/testdata/config-test.yaml"
declare out="${PROJECT_ROOT}/tests/testdata/stdout"
declare -i EPOCH_STABLE=1766164828

export EPOCH_STABLE

pushd . >/dev/null
cd "${PROJECT_ROOT}"
mkdir -p "${out}"
cargo -q run -- -q -n -c "$cfg" -t "$tpl" config > "${out}/cli_expected_config.txt"
cargo -q run -- -q -n -c "$cfg" -t "$tpl" start -o > "${out}/cli_expected_start.txt"
cargo -q run -- -q -n -c "$cfg" -t "$tpl" refresh -o > "${out}/cli_expected_refresh.txt"
popd >/dev/null
