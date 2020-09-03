#! /bin/bash

# A small tool to run golangci-lint across all relevant modules

HERE="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
CODE_DIR="$( realpath -e "$HERE/../code" )" || exit
CONFIG="$HERE/golangci.yml"
OUT_DIR="$( realpath -e "$HERE/../tools-output" )" || exit
cd $CODE_DIR || exit
MODULES=(deps/* go-fil-markets  lotus  specs-actors)
for MOD in ${MODULES[@]}; do
    cd "$CODE_DIR/$MOD" || exit
    MOD_NAME=$(basename $MOD)
    echo "Running GolangCI for $MOD"
    DEST="$OUT_DIR/${MOD_NAME}-golangci.out"
    CMD="golangci-lint run --config \"$CONFIG\" --color always"
    echo "# \$ cd \"$MOD\"" > "$DEST"
    echo "# \$ $CMD" >> "$DEST"
    eval $CMD >> "$DEST" 2>&1
done

