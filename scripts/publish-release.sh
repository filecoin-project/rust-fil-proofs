#!/usr/bin/env bash

RELEASE_BRANCH="spikes/release-publishing"
RELEASE_NAME="$CIRCLE_PROJECT_REPONAME-$(uname)"
RELEASE_PATH="$CIRCLE_ARTIFACTS/$RELEASE_NAME"
RELEASE_FILE="$RELEASE_PATH.tar.gz"
RELEASE_TAG="${CIRCLE_SHA1:0:16}"

# helper function to make clean get requests
# use like:
# request "/releases"
function get {
  curl \
    --verbose \
    --request GET \
    --header "Authorization: token $GITHUB_TOKEN" \
    --header "Content-Type: application/json" \
    "https://api.github.com/repos/$CIRCLE_PROJECT_USERNAME/$CIRCLE_PROJECT_REPONAME/$1"
}

# helper function to make clean post requests
# use like:
# post "/releases" "{\"foo\": \"bar\"}"
function post {
  curl \
    --verbose \
    --request POST \
    --header "Authorization: token $GITHUB_TOKEN" \
    --header "Content-Type: application/json" \
    --data "$2" \
    "https://api.github.com/repos/$CIRCLE_PROJECT_USERNAME/$CIRCLE_PROJECT_REPONAME/$1"
}

# helper function to make clean asset uploads
# use like:
# upload_release_asset "123456" "/path/to/file"
function upload_release_asset {
  curl \
    --verbose \
    --request POST \
    --header "Authorization: token $GITHUB_TOKEN" \
    --header "Content-Type: application/json" \
    --data-binary "@$2" \
    "https://uploads.github.com/repos/$CIRCLE_PROJECT_USERNAME/$CIRCLE_PROJECT_REPONAME/releases/$1/assets?name=$(basename $2)"
}

# make sure we're on the sanctioned branch
if [ "$CIRCLE_BRANCH" != "$RELEASE_BRANCH" ]; then
  echo "not on branch \"$BRANCH\", skipping publish"
  exit 0
fi

# make sure we have a token set, api requests won't work otherwise
if [ -z $GITHUB_TOKEN ]; then
  echo "\$GITHUB_TOKEN not set, publish failed"
  exit 1
fi

echo "preparing release file"

# pack up compiled lib and header
mkdir $RELEASE_PATH
cp target/release/*.a $RELEASE_PATH
cp filecoin-proofs/*.h $RELEASE_PATH
tar -czf $RELEASE_FILE $RELEASE_PATH/*

echo "release file created: $RELEASE_FILE"

# see if the release already exists by tag
RELEASE_RESPONSE=`get "releases/tags/$RELEASE_TAG"`

if [ "$(echo $RELEASE_RESPONSE | jq -r .message)" != "null" ]; then
  echo "creating release"

  # create it if it doesn't exist yet

  RELEASE_RESPONSE=`post "releases" "{
    \"tag_name\": \"$RELEASE_TAG\",
    \"target_commitish\": \"$CIRCLE_SHA1\",
    \"name\": \"$RELEASE_TAG\",
    \"body\": \"\"
  }"`
else
  echo "release already exists"
fi

echo "RELEASE_RESPONSE:"
echo $RELEASE_RESPONSE

RELEASE_ID=`echo $RELEASE_RESPONSE | jq -r '.id'`

upload_release_asset "$RELEASE_ID" "$RELEASE_FILE"

echo "release file uploaded"
