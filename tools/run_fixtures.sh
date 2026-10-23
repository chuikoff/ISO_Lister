#!/bin/bash
# run_fixtures.sh <IsoListerTest.exe> <dir> — run the standalone report CLI under Wine on every
# *.iso / *.img / *.bin / *.vhd / *.dmg / *.wim / *.esd in <dir>; writes <name>.report.txt next to
# the build and diffs against <dir>/expected/<name>.txt when present (version line ignored).
exe=$1; dir=$2; out=$(dirname "$exe")/fixtures; fail=0
mkdir -p "$out"
export WINEDEBUG=-all
for f in "$dir"/*.iso "$dir"/*.img "$dir"/*.bin "$dir"/*.vhd "$dir"/*.dmg "$dir"/*.wim "$dir"/*.esd; do
    [ -f "$f" ] || continue
    n=$(basename "$f")
    wine "$exe" "$(winepath -w "$f")" 2>"$out/$n.err" | iconv -f UTF-16LE -t UTF-8 | tr -d '\r' > "$out/$n.report.txt"
    if ! iconv -f UTF-16LE -t UTF-8 "$out/$n.err" 2>/dev/null | grep -q "VERIFY OK"; then echo "FAIL  $n (verify)"; fail=1; continue; fi
    exp="$dir/expected/${n%.*}.txt"
    if [ -f "$exp" ]; then
        if diff <(tail -n +2 "$exp" | tr -d '\r') <(tail -n +2 "$out/$n.report.txt") >/dev/null 2>&1; then echo "OK    $n (matches expected)"
        else echo "DIFF  $n"; diff <(tail -n +2 "$exp" | tr -d '\r') <(tail -n +2 "$out/$n.report.txt") | head -20; fail=1; fi
    else echo "OK    $n"; fi
done
exit $fail
