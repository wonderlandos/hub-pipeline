#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Commits the given paths of the public log, wonderlandos/hub-log, and pushes them there, rebasing over a concurrent
# push (check, sign and ca each push to hub-log; they write different files, so a rebase is never a conflict).
# Nothing to commit = nothing done. The pipeline repository itself is never written by a workflow.
#
#   commit-log.sh "<message>" <path>...
#
# HUB_LOG_DIR    the hub-log checkout, default ./log (the workflows check it out there with the environment's
#                deploy key, secret HUB_LOG_DEPLOY_KEY)
# HUB_LOG_REPO   default wonderlandos/hub-log; the checkout's origin must be exactly this repository on github.com
#
# Only the published folders may be committed: signed/, verdicts/, certs/, revocations.json and revoked.checkpoint.json
# (the database checkpoint at the root, where WolOS reads it: crates/core/src/cdn.rs RKDB_CHECKPOINTS). Any other path is
# refused, so a mistake in the pipeline cannot change hub-log's README or schema/.
set -euo pipefail
msg=${1:?usage: commit-log.sh <message> <path>...}
shift
[ $# -gt 0 ] || { echo "usage: commit-log.sh <message> <path>..." >&2; exit 2; }
dir=${HUB_LOG_DIR:-log}
repo=${HUB_LOG_REPO:-wonderlandos/hub-log}
for p in "$@"; do
    case $p in
    signed | signed/* | verdicts | verdicts/* | certs | certs/* | revocations.json | revoked.checkpoint.json) ;;
    *) echo "log: $p is not a published path of hub-log (signed/ verdicts/ certs/ revocations.json revoked.checkpoint.json)" >&2; exit 1 ;;
    esac
    case $p in *..*) echo "log: $p: no .. in a log path" >&2; exit 1 ;; esac
done
cd "$dir"
# The raw configured URL (not insteadOf-expanded): actions/checkout writes git@github.com:<repo>.git for an ssh key.
url=$(git config --get remote.origin.url || true)
case $url in
"git@github.com:$repo.git" | "git@github.com:$repo" | "https://github.com/$repo" | "https://github.com/$repo.git") ;;
*) echo "log: $dir is not a checkout of $repo (origin is '$url'); nothing pushed" >&2; exit 1 ;;
esac
git config user.name "wolos-hub-pipeline[bot]"
git config user.email "41898282+github-actions[bot]@users.noreply.github.com"
# A path that is not there is skipped (the log only grows; a first run may have no revocations.json yet).
present=()
for p in "$@"; do [ -e "$p" ] && present+=("$p"); done
[ ${#present[@]} -eq 0 ] || git add -- "${present[@]}"
if git diff --cached --quiet; then echo "log: nothing to commit"; exit 0; fi
git commit -q -m "$msg"
for _ in 1 2 3 4 5; do
    if git push -q origin HEAD:main; then echo "log: pushed $(git rev-parse --short HEAD) to $repo"; exit 0; fi
    git pull -q --rebase origin main
done
echo "log: could not push to $repo" >&2
exit 1
