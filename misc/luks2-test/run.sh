#!/bin/sh
# Read-only tests of the LUKS2 -> LVM2 -> ext4 stack against a real disk (macOS).
# Usage: run.sh <rawdisk e.g. /dev/rdisk2> <diskNsM of the LUKS partition> <passphrase-file> [quick]
# Needs read access to the raw disk, e.g.:  sudo chgrp staff /dev/rdisk2   (lasts until replug)
set -e
HERE=$(cd "$(dirname "$0")" && pwd); R=$HERE/../..; N=$R/app/src/main/native
J=${JAVA_HOME:?set JAVA_HOME}; OUT=${TMPDIR:-/tmp}/edsluks-test; rm -rf "$OUT"; mkdir -p "$OUT/cls"
DEV=$1; PART=$2; PASS=$3
OFF=$(diskutil info -plist "$PART" | plutil -extract PartitionMapPartitionOffset raw -)
SIZE=$(diskutil info -plist "$PART" | plutil -extract TotalSize raw -)
JI="-I$J/include -I$J/include/darwin"
cc -O2 -shared -fPIC -w -DAES_128 $JI -I$N/aes -I$N/crypto -I$N/argon2/include -I$N/argon2/src \
  $N/luks/edsluks.c $N/aes/aeskey.c $N/aes/aescrypt.c $N/aes/aestab.c $N/argon2/src/argon2.c $N/argon2/src/core.c \
  $N/argon2/src/encoding.c $N/argon2/src/ref.c $N/argon2/src/thread.c $N/argon2/src/blake2/blake2b.c -o "$OUT/libedsluks.dylib"
cc -O2 -shared -fPIC -w $JI -I$N/lwext4/include -I$N/ext4 $(cat $N/ext4/lwext4_defs.txt) $(ls $N/lwext4/src/*.c | grep -v mkfs) \
  $N/ext4/edsext4_core.c $N/ext4/edsext4_jni.c -o "$OUT/libedsext4.dylib"
FS=$R/app/src/main/java/com/sovworks/eds/fs
"$J/bin/javac" -nowarn -d "$OUT/cls" $R/app/src/main/java/com/sovworks/eds/luks2/*.java $FS/RandomAccessIO.java $FS/DataInput.java \
  $FS/DataOutput.java $FS/RandomStorageAccess.java $FS/ext4/Ext4Native.java $HERE/Luks2Info.java \
  $HERE/com/sovworks/eds/luks2/*.java $HERE/com/sovworks/eds/fs/ext4/StackTest.java
RUN="$J/bin/java -Xmx1g -Djava.library.path=$OUT -cp $OUT/cls"
echo "== crypto self-test";  $RUN com.sovworks.eds.luks2.CryptoSelfTest
echo "== header inspect";    $RUN Luks2Info "$DEV" "$(diskutil info -plist "${PART%s*}" | plutil -extract TotalSize raw -)"
echo "== header mutations";  $RUN com.sovworks.eds.luks2.MutationTest "$DEV" "$OFF" "$PASS"
echo "== full stack + dpkg md5 verification"
if [ "$4" = quick ]; then V="dpkg:bash,systemd"; else V="dpkg:*"; fi
$RUN -Dquiet=true com.sovworks.eds.fs.ext4.StackTest "$DEV" "$OFF" "$SIZE" "$PASS" usr/lib/os-release "$V"
