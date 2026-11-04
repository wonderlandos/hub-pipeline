#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Commits the given paths to the current branch as the public log and pushes, rebasing over a concurrent push
# (the check and sign workflows share one concurrency group, so a rebase is rare and never a conflict:
# they write different files). Nothing to commit = nothing done.
#
#   commit-log.sh "<message>" <path>...
set -euo pipefail
msg=${1:?usage: commit-log.sh <message> <path>...}
shift
git config user.name "wolos-hub-index[bot]"
git config user.email "41898282+github-actions[bot]@users.noreply.github.com"
git add -- "$@"
if git diff --cached --quiet; then echo "log: nothing to commit"; exit 0; fi
git commit -q -m "$msg"
for _ in 1 2 3 4 5; do
    if git push -q origin HEAD:main; then echo "log: pushed $(git rev-parse --short HEAD)"; exit 0; fi
    git pull -q --rebase origin main
done
echo "log: could not push" >&2
exit 1
