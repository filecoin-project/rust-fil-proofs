#!/usr/bin/env bash
set -Eeuo pipefail

# pin-params.sh
#
# - Post the directory of params to cluster.ipfs.io
# - Grab the CID for the previous params from proofs.filecoin.io
# - Add the old params as a `prev` dir to the new params dir to keep them around.
# - Pin the new cid on cluster
# - Publish the new cid as a dnslink to proofs.filecoin.io
# - The gateways will pin the new dir by checking proofs.filecoin.io hourly.
#
# Requires:
#  - `ipfs-cluster-ctl` - download from https://dist.ipfs.io/#ipfs-cluster-ctl
#  - `npx`, as provide `npm` >= v6
#  - `ipfs`
#
# You _must_ provide the following env vars
#
#  - CLUSTER_TOKEN - the basic auth string as "username:password"
#  - DNSIMPLE_TOKEN - an api key for a dnsimple account with a zone for proofs.filecoin.io
#
# Optional: you can override the input dir by passing a path as the first param.
#
# Usage:
#   CLUSTER_TOKEN="user:pass" DNSIMPLE_TOKEN="xyz" ./pin-params.sh
#

INPUT_DIR=${1:-"/var/tmp/filecoin-proof-parameters"}
: "${CLUSTER_TOKEN:?please set CLUSTER_TOKEN env var}"
: "${DNSIMPLE_TOKEN:?please set DNSIMPLE_TOKEN env var}"

echo "checking $INPUT_DIR"

# Grab the version number from the files in the dir.
# Fail if more than 1 version or doesnt match a version string like vNN, e.g v12
if ls -A $INPUT_DIR &> /dev/null; then
  # version will be a list if there is more than one...
  VERSION=$(ls $INPUT_DIR | sort -r | cut -c 1-3 | uniq)
  echo found $VERSION

  if [[ $(echo $VERSION | wc -w) -eq 1 && $VERSION =~ ^v[0-9]+ ]]; then
    # we have 1 version, lets go...
    COUNT=$(ls -l $INPUT_DIR | wc -l | xargs echo -n)
    echo "adding $COUNT files to ipfs..."

  else
    echo "Error: input dir should contain just the current version of the params"
    exit 1
  fi
else
  echo "Error: input dir '$INPUT_DIR' should contain the params"
  exit 1
fi

CLUSTER_HOST="/dnsaddr/filecoin.collab.ipfscluster.io"
ADDITIONAL_CLUSTER_HOST="/dnsaddr/cluster.ipfs.io"
CLUSTER_PIN_NAME="filecoin-proof-parameters-$VERSION"
DNSLINK_DOMAIN="proofs.filecoin.io"

# Add and pin to collab cluster. After this it will be on 1 peer and pin requests
# will have been triggered for the others.
ROOT_CID=$(ipfs-cluster-ctl \
  --host $CLUSTER_HOST \
  --basic-auth $CLUSTER_TOKEN \
  add --quieter \
  --local \
  --name $CLUSTER_PIN_NAME \
  --recursive $INPUT_DIR )

echo "ok! root cid is $ROOT_CID"

# Pin to main cluster additionally.
ipfs-cluster-ctl \
    --host $ADDITIONAL_CLUSTER_HOST \
    --basic-auth $CLUSTER_TOKEN \
    pin add $ROOT_CID \
    --no-status

echo "ok! Pin request sent to additional cluster"

# Publist the new cid to the dnslink
npx dnslink-dnsimple --domain $DNSLINK_DOMAIN --link "/ipfs/$ROOT_CID"

echo "done!"
