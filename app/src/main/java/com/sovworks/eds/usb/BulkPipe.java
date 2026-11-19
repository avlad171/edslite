package com.sovworks.eds.usb;

import java.io.Closeable;

/**
 * The raw USB operations the Bulk-Only Transport needs. Implemented on Android by
 * {@link AndroidBulkPipe} (UsbDeviceConnection) and by a simulated device in the desktop tests.
 *
 * Transfer methods return the number of bytes transferred, or a negative value on any error
 * (stall, timeout, disconnect: Android does not tell them apart).
 */
public interface BulkPipe extends Closeable
{
    int maxPacketSize();

    int bulkOut(byte[] buf, int off, int len, int timeoutMs);

    int bulkIn(byte[] buf, int off, int len, int timeoutMs);

    /** CLEAR_FEATURE(ENDPOINT_HALT) on the IN (true) or OUT (false) endpoint. */
    boolean clearHalt(boolean in);

    /** Class request "Bulk-Only Mass Storage Reset" (USB MSC BOT 1.0, 3.1). */
    boolean massStorageReset();

    /** False once the device is known to be gone (unplugged). */
    boolean isConnected();

    @Override
    void close();
}
