#!/usr/bin/env bash
# set -x
set -Eeuo pipefail

# pin-params.sh
#
# Adds param files to local repo, links them with previous versions, pin them
# to ipfs-cluster, and update the published dnslink...
#
# Before you run it:
# - Clear out /var/tmp/filecoin-proof-parameters
# - Create the latest params with `cargo run --release --bin paramcache`
#
# What it does:
# - Add /var/tmp/filecoin-proof-parameters to the local ipfs node
# - Copy the previous params from proofs.filecoin.io to the local ipfs mfs
# - Link the last 3 version in a directory in the local ipfs mfs and grab the cid
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
CLUSTER_PRIMARY="/dns4/cluster0.fsn.dwebops.pub/tcp/4001/p2p/QmUEMvxS2e7iDrereVYc5SWPauXPyNwxcy9BXZrC1QTcHE"
CLUSTER_PIN_NAME="filecoin-proof-parameters-$VERSION"
DNSLINK_DOMAIN="proofs.filecoin.io"

# Pin to ipfs
ROOT_CID=$(ipfs add --quieter --recursive $INPUT_DIR)
echo "ok! root cid for $VERSION is $ROOT_CID"

echo "linking in previous versions..."

# Connect to cluster to speed up discovery
ipfs swarm connect $CLUSTER_PRIMARY

# trim off the /ipfs prefix, so it's consistent with the other vars
PREV_CID=$(ipfs dns $DNSLINK_DOMAIN | cut -c 7-)

# this is needed becuase ipfs files rm -f errors if the file doesn't exist
function removeMfsDir () {
  if ipfs files stat $1 &> /dev/null; then
    ipfs files rm -r $1
  fi
}

# Reset and create matching dir in the mfs with the previous published dir cid in it.
removeMfsDir $INPUT_DIR
ipfs files mkdir -p "$(dirname $INPUT_DIR)"
ipfs files cp /ipfs/$PREV_CID $INPUT_DIR

# remove folder for current version if it already exists...
removeMfsDir $INPUT_DIR/$VERSION
ipfs files cp /ipfs/$ROOT_CID $INPUT_DIR/$VERSION

# move things around till we have the last 3 versions in the mfs mirror world version of the $INPUT_DIR
TMP_MFS_DIR=/var/tmp/pin-params
removeMfsDir $TMP_MFS_DIR
ipfs files mkdir -p $TMP_MFS_DIR

# copy just the last 3 versions to a tmp dir
ipfs files ls $INPUT_DIR | cut -c 2- | sort -n | tail -3 | xargs -I {} ipfs files cp $INPUT_DIR/v{} $TMP_MFS_DIR/v{}
# reset the working dir and copy the last 3 versions back
ipfs files rm -r $INPUT_DIR
ipfs files cp $TMP_MFS_DIR $INPUT_DIR
ipfs files rm -r $TMP_MFS_DIR

LINKED_CID=$(ipfs files stat --format="<hash>" $INPUT_DIR)
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
npx dnslink-dnsimple --domain $DNSLINK_DOMAIN --link "/ipfs/$LINKED_CID"

echo "done!"
