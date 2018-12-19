#!/usr/bin/env bash

# hacky for now:
apt-get install -yqq jq

BRANCH="spikes/release-publishing"

if [ "$CIRCLE_BRANCH" != "$BRANCH" ]; then
  echo "not on branch \"$BRANCH\", skipping publish"
  exit 0
fi

if [ -z $GITHUB_TOKEN ]; then
  echo "\$GITHUB_TOKEN not set, publish failed"
  exit 1
fi

echo "packing build"

BUILD_NAME="$CIRCLE_PROJECT_REPONAME-$(uname)"
BUILD_DIR="$CIRCLE_ARTIFACTS/$BUILD_NAME"
BUILD_TAR="$BUILD_DIR.tar.gz"

mkdir $BUILD_DIR
cp target/release/*.a $BUILD_DIR
cp filecoin-proofs/*.h $BUILD_DIR
tar -czf $BUILD_TAR $BUILD_DIR/*

echo "created tar: $BUILD_TAR"

echo "creating release"

RELEASE_URL="https://api.github.com/repos/$CIRCLE_PROJECT_USERNAME/$CIRCLE_PROJECT_REPONAME/releases"

RELEASE_NAME="${CIRCLE_SHA1:0:16}"
RELEASE_DATA="{
  \"tag_name\": \"$RELEASE_NAME\",
  \"target_commitish\": \"$CIRCLE_SHA1\",
  \"name\": \"$RELEASE_NAME\",
  \"body\": \"\"
}"

CREATE_RELEASE_RESPONSE=`
  curl \
    --request POST \
    --header "Authorization: token $GITHUB_TOKEN" \
    --header "Content-Type: application/json" \
    --data "$RELEASE_DATA" \
    "$RELEASE_URL"
`

RELEASE_ID=`echo $CREATE_RELEASE_RESPONSE | jq -r '.id'`
UPLOAD_URL=`echo $CREATE_RELEASE_RESPONSE | jq -r '.upload_url' | cut -d'{' -f1`

echo "release created: $RELEASE_ID"

UPLOAD_RELEASE_RESPONSE=`
  curl \
    --request POST \
    --header "Authorization: token $GITHUB_TOKEN" \
    --header "Content-Type: application/octet-stream" \
    --data-binary @$BUILD_TAR \
    "$UPLOAD_URL?name=$BUILD_NAME.tar.gz"
`

echo "release build published"
