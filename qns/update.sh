#!/bin/bash
set -e

if [[ "$1" == "-p" ]]; then
  shift
  push=1
else
  push=0
fi

branch="${1:-$(git rev-parse --abbrev-ref HEAD)}"
if [[ "$branch" == "main" ]]; then
  tag="neqoquic/neqo-qns:latest"
else
  tag="neqoquic/neqo-qns:${branch}"
fi

cd "$(dirname "$0")"

rev=$(git log -n 1 --format='format:%H')
if [[ "$rev" == "$(cat ".last-update-$branch")" ]]; then
  echo "No change since $rev."
  exit 0
fi

# This makes the local .git directory the source, allowing for the current
# build to be build and pushed.
[[ ! -e .git ]] || ! echo "Found .git directory. Script still active. Exiting."
trap 'rm -rf .git' EXIT
cp -R ../.git .git

docker build -t "$tag" --build-arg NEQO_BRANCH="$branch" .
if [[ "$push" == "1" ]]; then
  docker login
  docker push "$tag"
fi

echo "$rev" > ".last-update-$branch"
