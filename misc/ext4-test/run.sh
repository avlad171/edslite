#!/bin/sh
# Builds the ext4 core natively and checks it against images made by mke2fs -d.
set -e
HERE=$(cd "$(dirname "$0")" && pwd); N=$HERE/../../app/src/main/native
OUT=${TMPDIR:-/tmp}/edsext4-test; rm -rf "$OUT"; mkdir -p "$OUT/src/sub/deeper"
MKE2FS=$(brew --prefix e2fsprogs 2>/dev/null)/sbin/mke2fs; [ -x "$MKE2FS" ] || MKE2FS=mke2fs
cc -O1 -g -fsanitize=address,undefined -Wall -I"$N/lwext4/include" -I"$N/ext4" \
   $(cat "$N/ext4/lwext4_defs.txt") \
   "$N"/lwext4/src/*.c "$N/ext4/edsext4_core.c" "$HERE/ext4walk.c" -o "$OUT/ext4walk"
# test data: empty, tiny, multi-block, sparse, many entries (forces htree), unicode
: > "$OUT/src/empty"; echo hello > "$OUT/src/tiny.txt"
head -c 5000000 /dev/urandom > "$OUT/src/sub/random.bin"
dd if=/dev/urandom of="$OUT/src/sub/deeper/sparse" bs=1k seek=3000 count=7 2>/dev/null
printf x | dd of="$OUT/src/sub/tailhole" bs=1 seek=20000 2>/dev/null; dd if=/dev/urandom of="$OUT/src/sub/midhole" bs=4096 count=1 2>/dev/null; dd if=/dev/urandom of="$OUT/src/sub/midhole" bs=4096 seek=40 count=1 conv=notrunc 2>/dev/null; dd if=/dev/zero of="$OUT/src/sub/midhole" bs=1 seek=300000 count=0 2>/dev/null
for i in $(seq 1 600); do echo $i > "$OUT/src/sub/f_$i"; done
echo ü > "$OUT/src/Ünïcødé ñame.txt"
# symlinks (resolved with chroot semantics: absolute targets and ".." stay inside the volume)
LONGNAME=$(printf 'L%.0s' $(seq 1 150)); echo long > "$OUT/src/sub/$LONGNAME"
mkdir "$OUT/src/links"; cd "$OUT/src/links"
ln -s ../tiny.txt rel_file; ln -s /tiny.txt abs_file; ln -s ../sub/deeper dir
ln -s chain2 chain1; ln -s rel_file chain2; ln -s loop2 loop1; ln -s loop1 loop2; ln -s nothing_here broken
ln -s ../../../../../../tiny.txt escape; ln -s /../../etc/passwd escape_abs; ln -s "../sub/$LONGNAME" long; ln -s . self
mkdir c; for i in $(seq 0 38); do ln -s "c$((i+1))" "c/c$i"; done; ln -s ../../tiny.txt c/c39; ln -s c0 c/over
cd "$OUT/src"; ln -s sub usrbin; cd "$HERE"
fnv() { python3 -c "import sys;d=open(sys.argv[1],'rb').read();h=1469598103934665603
for b in d: h=((h^b)*1099511628211)&0xFFFFFFFFFFFFFFFF
print('F %d %016x'%(len(d),h))" "$OUT/src/$1"; }
cat > "$OUT/checks" <<CHK
links
links/rel_file
links/abs_file
links/dir
links/dir/sparse
links/dir/../random.bin
links/chain1
links/loop1
links/broken
links/escape
links/escape_abs
links/long
links/self/self/self/rel_file
links/rel_file/x
usrbin/random.bin
links/c/c0
links/c/over
CHK
T=$(fnv tiny.txt)
cat > "$OUT/checks.expected" <<EXP
links D abs_file@ c chain1@ chain2@ dir@ escape@ long@ rel_file@ self@
links/rel_file $T
links/abs_file $T
links/dir D sparse
links/dir/sparse $(fnv sub/deeper/sparse)
links/dir/../random.bin $(fnv sub/random.bin)
links/chain1 $T
links/loop1 ERR ELOOP
links/broken ERR ENOENT
links/escape $T
links/escape_abs ERR ENOENT
links/long $(fnv "sub/$LONGNAME")
links/self/self/self/rel_file $T
links/rel_file/x ERR ENOTDIR
usrbin/random.bin $(fnv sub/random.bin)
links/c/c0 $T
links/c/over ERR ELOOP
EXP
expected() { (cd "$OUT/src" && find . -type f | sort | while read f; do
  python3 -c "import sys;h=1469598103934665603
for b in open(sys.argv[1],'rb').read(): h=((h^b)*1099511628211)&0xFFFFFFFFFFFFFFFF
print('F %d %s %016x'%(len(open(sys.argv[1],'rb').read()),sys.argv[1][1:],h))" "$f"; done); }
expected | LC_ALL=C sort > "$OUT/expected"
fail=0
for opts in "-t ext4" "-t ext4 -b 1024" "-t ext4 -O ^metadata_csum,^64bit" "-t ext3" "-t ext2" "-t ext4 -O ^extent,^64bit"; do
  img="$OUT/img"; rm -f "$img"
  $MKE2FS -q -F $opts -d "$OUT/src" "$img" 64M
  "$OUT/ext4walk" "$img" > "$OUT/got" 2>"$OUT/err" || { echo "FAIL [$opts]: $(cat $OUT/got | grep ERR; cat $OUT/err | tail -3)"; fail=1; continue; }
  if grep "^F" "$OUT/got" | LC_ALL=C sort | diff -q - "$OUT/expected" >/dev/null; then echo "OK   [$opts] ($(grep -c . $OUT/got) entries)"; else echo "FAIL [$opts] content mismatch"; grep "^F" "$OUT/got" | LC_ALL=C sort | diff - "$OUT/expected" | head; fail=1; fi
  "$OUT/ext4walk" "$img" check < "$OUT/checks" > "$OUT/checks.got" 2>"$OUT/err"
  if diff -q "$OUT/checks.got" "$OUT/checks.expected" >/dev/null; then echo "OK   [$opts] symlinks ($(grep -c . $OUT/checks) cases)"; else echo "FAIL [$opts] symlinks"; diff "$OUT/checks.got" "$OUT/checks.expected" | head -20; fail=1; fi
done
# I/O errors at every point (USB drive unplugged mid-operation): every run must end cleanly, with
# no crash, assertion or sanitizer report. Both a full walk (stops at the first error) and the
# check list (keeps going after errors, like the file manager) are run for each failure point.
for opts in "-t ext4" "-t ext2"; do
  img="$OUT/fimg"; rm -f "$img"; $MKE2FS -q -F $opts -d "$OUT/src" "$img" 64M
  R=$("$OUT/ext4walk" "$img" 2>&1 >/dev/null | sed -n 's/^reads=//p'); STEP=$(( R / 300 + 1 )); bad=0; runs=0
  n=0; while [ $n -le $R ]; do
    for mode in walk check; do
      runs=$((runs+1))
      if [ $mode = check ]; then EDSEXT4_FAIL_AFTER=$n ASAN_OPTIONS=exitcode=99 "$OUT/ext4walk" "$img" check < "$OUT/checks" >/dev/null 2>"$OUT/ferr"; rc=$?
      else EDSEXT4_FAIL_AFTER=$n ASAN_OPTIONS=exitcode=99 "$OUT/ext4walk" "$img" >/dev/null 2>"$OUT/ferr"; rc=$?; fi
      if [ $rc -ne 0 ]; then bad=$((bad+1)); [ $bad -le 3 ] && { echo "  crash at read $n ($mode, rc=$rc):"; grep -E "Assertion|assert|ERROR: AddressSanitizer|runtime error|SUMMARY" "$OUT/ferr" | head -3; }; fi
    done
    n=$((n+STEP))
  done
  if [ $bad -eq 0 ]; then echo "OK   [$opts] I/O error injection: $runs runs over $R reads, no crashes"; else echo "FAIL [$opts] I/O error injection: $bad of $runs runs crashed"; fail=1; fi
done
# Must never write: image hash unchanged after walk
shasum "$img" > "$OUT/h1"; "$OUT/ext4walk" "$img" >/dev/null 2>&1; shasum "$img" | diff -q - "$OUT/h1" >/dev/null && echo "OK   image unmodified" || { echo "FAIL image modified"; fail=1; }
exit $fail
