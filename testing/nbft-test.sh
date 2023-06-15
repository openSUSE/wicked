#! /bin/bash
trap 'echo ERROR in $BASH_COMMAND; exit 1' ERR
set -E

: "${NBFT:=../extensions/nbft}"
: "${TMPDIR:=/tmp}"
: "${MAC:=52:54:00:a2:a7:b2}"
: "${IFACE:=nbft0}"

TMPD=$(mktemp -d --tmpdir)
trap 'rm -rf "$TMPD"' 0

TESTS=0

prepare_dir() {
    local dir=$1
    mkdir -p "$dir/proc/net/vlan"
    cat >"$dir/proc/net/vlan/config" <<-EOF
	VLAN Dev name	 | VLAN ID
	Name-Type: VLAN_NAME_TYPE_RAW_PLUS_VID_NO_PAD
	nbft0.5        | 5  | nbft0
	EOF
    mkdir -p "$dir/sys/class/net/$IFACE"
    echo "$MAC" >"$dir/sys/class/net/$IFACE/address"
    echo 2 >"$dir/sys/class/net/$IFACE/ifindex"

    mkdir -p "$dir/sys/firmware/acpi/tables"
    : >"$dir/sys/firmware/acpi/tables/NBFT"

    mkdir -p "$dir/sys/class/nvme-fabrics"
}

do_test() {
    local dif res dir err
    TESTS=$((TESTS + 1))

    dir=${1#*/}
    echo -n "=== nbft-test: $TESTS. $dir"

    mkdir -p "$TMPD/$dir"
    prepare_dir "$TMPD/$dir"
    cp "$1"/nbft-hfi.json "$TMPD/$dir/nbft.json"

    err=0
    res=0

    bash "$NBFT" -r "$TMPD/$dir" >"$TMPD/$dir/nbft.out" || err=$?
    dif=$(diff -u "$1/nbft.out" "$TMPD/$dir/nbft.out") || res=$?

    [[ "$err" -eq 0 ]] || echo -n " (nbft exit status: $err) "
    if [[ "$res" -eq 0 ]]; then
        echo " ... OK"
        return 0
    else
        echo " ... ERROR"
        echo "$dif"
        return 1
    fi
}

test_bad() {
    local output dif res dir err
    TESTS=$((TESTS + 1))

    dir=${1#*/}
    echo -n "=== nbft-test: $TESTS. missing $2"

    rm -rf "$TMPD/bad"
    mkdir -p "$TMPD/bad"
    prepare_dir "$TMPD/bad"
    cp "$1"/nbft-hfi.json "$TMPD/bad/nbft.json"
    rm -rf "$TMPD/bad$2"
    output=$(bash "$NBFT" -r "$TMPD/bad" >"$TMPD/bad/nbft.out") || err=$?

    [[ "$err" -eq 0 ]] || echo -n " (nbft exit status: $err) "
    if [[ "$output" ]]; then
        echo " ... ERROR"
        echo "$output"
        return 1
    else
        echo " ... OK"
        return 0
    fi
}

ERRORS=0

cd "$srcdir"
for dir in nbft/*; do
    do_test "$dir" || ERRORS=$((ERRORS + 1))
done

test_bad nbft/dhcp-simple /sys/class/nvme-fabrics
test_bad nbft/dhcp-simple /sys/firmware/acpi/tables/NBFT
test_bad nbft/dhcp-simple /sys/firmware/acpi
test_bad nbft/dhcp-simple /sys/class/net

echo "=== TESTS = $TESTS, ERRORS = $ERRORS"
[[ "$ERRORS" -eq 0 ]]
