#!/bin/bash
#
# Helper script to launch Ghidra coverage analysis with given kAFL traces and target ELF.
#
# Copyright 2020 Intel Corporation
# SPDX-License-Identifier: MIT

set -e
set -u

SCRIPT_DIR=$(realpath $(dirname $0))
GHIDRA_ROOT=$(realpath ${SCRIPT_DIR}/../kAFL/kafl/ghidra_10.1.3_PUBLIC)
KAFL_ROOT=$(realpath ${SCRIPT_DIR}/../kAFL/kafl)

function fail {
	echo -e "\nError: $@\n" >&2
	echo -e "Usage:\n\t$0 <kafl_workdir> <target_binary> <script>\n" >&2
	exit 1
}

test -z ${GHIDRA_ROOT-} && fail "Could not find \$GHIDRA_ROOT. Missing 'make env'?"
test -z ${KAFL_ROOT-} && fail "Could not find \$KAFL_ROOT. Missing 'make env'?"
test $# -ge 3 || fail "Missing arguments."

WORKDIR="$(realpath $1)" # kAFL work dir with traces/ folder
TARGET="$(realpath $2)"  # original target input (tested with basic ELF file loaded as -kernel)
SCRIPT="$(realpath $3)"  # script to run

BIN=$GHIDRA_ROOT/support/analyzeHeadless
PROJDIR=$WORKDIR/../ghidra
PROJ=cov_analysis

test -d $PROJDIR   || mkdir $PROJDIR || fail "Could not create target folder $PROJDIR"
test -f "$BIN"     || fail "Could not find $BIN. Check ghidra install."
test -f "$TARGET"  || fail "Could not find target binary at $TARGET"
test -f "$SCRIPT"  || fail "Could not find coverage analysis script at $SCRIPT"

# Check if traces have been generated and optionally create unique edges file
test -d "$WORKDIR/traces/" || fail "Could not find traces/ folder in workdir."
$SCRIPT_DIR/unique_edges.sh $WORKDIR

# create project and import binary - slow but only required once per binary
test -f $PROJDIR/$PROJ.gpr || $BIN $PROJDIR $PROJ -import $TARGET
# analyse coverage
$BIN $PROJDIR $PROJ -noanalysis -process $(basename $TARGET) -prescript GetAndSetAnalysisOptionsScript.java -scriptPath "$(dirname $SCRIPT)" -postscript "$(basename $SCRIPT)" ${@:4}
