#!/bin/bash
set -e

tag="neqoquic/neqo-qns:${1:-latest}"
branch="${1:-main}"

cd "$(dirname "$0")"

rev=$(git log -n 1 --format='format:%H' -- .)
[[ "$rev" != "$(cat .last-update)" ]] || (echo "No change since $rev."; exit 0)

[[ ! -e .git ]] || ! echo "Found .git directory. Script still active. Exiting."
trap 'rm -rf .git' EXIT
cp -R ../.git .git

docker build -t "$tag" --build-arg NEQO_BRANCH="$branch" .
docker login
docker push "$tag"

echo "$rev" > .last-update
