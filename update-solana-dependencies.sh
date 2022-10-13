#!/usr/bin/env bash
#
# Updates the solana version in all the SPL crates
#

here="$(dirname "$0")"

solana_ver=$1
if [[ -z $solana_ver ]]; then
  echo "Usage: $0 <new-solana-version>"
  exit 1
fi

if [[ $solana_ver =~ ^v ]]; then
  # Drop `v` from v1.2.3...
  solana_ver=${solana_ver:1}
fi

cd "$here"

echo "Updating Solana version to $solana_ver in $PWD"

if ! git diff --quiet && [[ -z $DIRTY_OK ]]; then
  echo "Error: dirty tree"
  exit 1
fi

declare tomls=()
while IFS='' read -r line; do tomls+=("$line"); done < <(find . -name Cargo.toml)

crates=(
  solana-account-decoder
  solana-banks-client
  solana-banks-server
  solana-bpf-loader-program
  solana-clap-utils
  solana-clap-v3-utils
  solana-cli-config
  solana-cli-output
  solana-client
  solana-core
  solana-logger
  solana-notifier
  solana-program
  solana-program-test
  solana-remote-wallet
  solana-runtime
  solana-sdk
  solana-stake-program
  solana-test-validator
  solana-transaction-status
  solana-validator
)

set -x
for crate in "${crates[@]}"; do
  sed -i -e "s#\(${crate} = \"\).*\(\"\)#\1=$solana_ver\2#g" "${tomls[@]}"
done

