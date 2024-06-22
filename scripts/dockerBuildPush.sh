#!/bin/bash -e

version=$1

if [ -z "$version" ]; then
  echo 'Missing version' >&2
  exit 1
fi

versionArr=(${version//./ })
major_version=${versionArr[0]}

docker buildx build \
  --platform linux/amd64,linux/arm64 \
  --tag idzingirai/cognito-local:latest \
  --tag idzingirai/cognito-local:${major_version}-latest \
  --tag idzingirai/cognito-local:${version} \
  --push \
  .

echo "{\"name\":\"Docker\",\"url\":\"https://hub.docker.com/r/idzingirai/cognito-local\"}"