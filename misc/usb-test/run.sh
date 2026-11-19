#!/bin/sh
# Desktop tests for the USB mass-storage transport (simulated device with fault injection)
# and the GPT/MBR parser. No hardware needed.
set -e
HERE=$(cd "$(dirname "$0")" && pwd); R=$HERE/../..
J=${JAVA_HOME:?set JAVA_HOME}; OUT=${TMPDIR:-/tmp}/edsusb-test; rm -rf "$OUT"; mkdir -p "$OUT"
S=$R/app/src/main/java/com/sovworks/eds
"$J/bin/javac" -nowarn -d "$OUT" $S/usb/BulkPipe.java $S/usb/UsbMassStorage.java $S/usb/PartitionTable.java \
  $S/luks2/*.java $S/fs/RandomAccessIO.java $S/fs/DataInput.java $S/fs/DataOutput.java $S/fs/RandomStorageAccess.java \
  $HERE/com/sovworks/eds/usb/UsbSimTest.java
"$J/bin/java" -cp "$OUT" com.sovworks.eds.usb.UsbSimTest
