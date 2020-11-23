#!/usr/bin/env bash

CMDS=$(cat <<EOF

set -e

# Creates a temporary directory in which we build rust-fil-proofs and capture
# performance metrics. The name of the directory (today's UTC seconds plus 24
# hours) serves as a cleanup mechanism; before metrics are captured, any expired
# directories are removed.

_one_day_from_now=\$((\$(date +%s) + 86400))
_metrics_dir=/tmp/metrics/\$_one_day_from_now

# Find and prune any stale metrics directories.
find /tmp/metrics/ -maxdepth 1 -mindepth 1 -type d -printf "%f\n" \
    | xargs -I {} bash -c 'if (({} < \$(date +%s))) ; then rm -rf /tmp/metrics/{} ; fi' 2> /dev/null

# Make sure hwloc library is available on the remote host.
apt-get -y -q install libhwloc-dev > /dev/null 2>&1

# Make sure rust is installed on the remote host.
curl https://sh.rustup.rs -sSf | sh -s -- -y > /dev/null 2>&1
source $HOME/.cargo/env  /dev/null 2>&1

git clone -b $1 --single-branch https://github.com/filecoin-project/rust-fil-proofs.git \$_metrics_dir || true

cd \$_metrics_dir

./fil-proofs-tooling/scripts/retry.sh 42 10 60000 \
    ./fil-proofs-tooling/scripts/with-lock.sh 42 /tmp/metrics.lock \
    ./fil-proofs-tooling/scripts/with-dots.sh \
    ${@:3}
EOF
)

ssh -q $2 "$CMDS"
