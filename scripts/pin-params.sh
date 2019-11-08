#!/usr/bin/env bash
set -Eeuo pipefail

# pin-params.sh
#
# - Add the directory of params to the local ipfs node
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

CLUSTER_HOST="/dnsaddr/cluster.ipfs.io"
CLUSTER_PRIMARY="/dns4/cluster0.fsn.dwebops.pub/udp/4001/quic/p2p/QmUEMvxS2e7iDrereVYc5SWPauXPyNwxcy9BXZrC1QTcHE"
CLUSTER_PIN_NAME="filecoin-proof-parameters-$VERSION"
DNSLINK_DOMAIN="proofs.filecoin.io"

# Pin to ipfs
ROOT_CID=$(ipfs add --quieter --recursive $INPUT_DIR)
echo "ok! root cid is $ROOT_CID"

echo "linking to previous version..."
# trim off the /ipfs prefix, so it's consistent with the other vars
PREV_CID=$(ipfs dns $DNSLINK_DOMAIN | cut -c 7-)

# Add a `prev` dir to the new params dir that links back to the older params
LINKED_CID=$(ipfs object patch add-link $ROOT_CID prev $PREV_CID)

# guard against multiple runs with no change...
# if we remove the `prev` dir from the last published PREV_CID and it matches
# the current ROOT_DIR, then dont nest it inside itself again.
if ipfs object stat $PREV_CID/prev > /dev/null; then
  PREV_ROOT_CID=$(ipfs object patch rm-link $PREV_CID prev)
  if [[ $PREV_ROOT_CID == "$ROOT_CID" ]]; then
    LINKED_CID=$PREV_CID
    echo "linked cid is already published, re-using $PREV_CID"
    echo "continuing to ensure $PREV_CID is pinned to cluster"
  fi
fi

echo "ok! linked cid is $LINKED_CID"
echo "pinning linked cid to cluster..."

# Connect to cluster to speed up discovery
ipfs swarm connect $CLUSTER_PRIMARY

# Ask cluster to fetch the linked cid from us
ipfs-cluster-ctl \
  --host $CLUSTER_HOST \
  --basic-auth $CLUSTER_TOKEN \
  pin add $LINKED_CID \
  --name $CLUSTER_PIN_NAME \
  --wait

# Publist the new cid to the dnslink
npx dnslink-dnsimple --domain proofs.filecoin.io --link "/ipfs/$LINKED_CID"

echo "done!"
