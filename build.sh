#!/bin/sh
# sh build.sh           build ./nginxviz for this machine
# sh build.sh release   cross-compile static binaries for every platform into dist/
# VERSION=v1.2.3 sets what `nginxviz --version` reports (default: dev)
set -e
cd "$(dirname "$0")"
export CGO_ENABLED=0
VERSION=${VERSION:-dev}
if [ "$1" != release ]; then
    go build -trimpath -ldflags="-s -w -X main.version=$VERSION" -o nginxviz .
    echo "built $(pwd)/nginxviz"
    exit 0
fi
rm -rf dist
mkdir dist
for target in darwin/arm64 darwin/amd64 linux/amd64 linux/arm64 linux/arm linux/386 freebsd/amd64 windows/amd64 windows/arm64; do
    os=${target%/*}
    arch=${target#*/}
    name=nginxviz-$os-$arch
    [ "$arch" = arm ] && name=nginxviz-$os-armv7
    [ "$os" = windows ] && name=$name.exe
    GOOS=$os GOARCH=$arch GOARM=7 go build -trimpath -ldflags="-s -w -X main.version=$VERSION" -o "dist/$name" .
    echo "dist/$name"
done
