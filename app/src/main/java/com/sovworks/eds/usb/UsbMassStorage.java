package com.sovworks.eds.usb;

import com.sovworks.eds.luks2.Luks2Header;

import java.io.Closeable;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;

/**
 * READ-ONLY block access to a USB mass-storage device over the Bulk-Only Transport (BOT)
 * with SCSI commands.
 *
 * Read-only by construction:
 *  - every command goes through {@link #transport}, which refuses any SCSI opcode not in
 *    {@link #ALLOWED_OPCODES} (identify / readiness / sense / capacity / read);
 *  - the only bytes ever sent to the device are 31-byte command blocks built here; there is
 *    no data-out phase anywhere in this class.
 *
 * Error handling follows BOT 1.0 section 5.3/6.6: stalls are cleared, invalid or phase-error
 * status triggers reset recovery, and reads (idempotent) are retried a few times.
 */
public final class UsbMassStorage implements Luks2Header.Source, Closeable
{
    public static final int OP_TEST_UNIT_READY = 0x00, OP_REQUEST_SENSE = 0x03, OP_INQUIRY = 0x12,
            OP_READ_CAPACITY10 = 0x25, OP_READ10 = 0x28, OP_READ16 = 0x88, OP_SERVICE_ACTION_IN16 = 0x9E;
    static final int[] ALLOWED_OPCODES = {OP_TEST_UNIT_READY, OP_REQUEST_SENSE, OP_INQUIRY,
            OP_READ_CAPACITY10, OP_READ10, OP_READ16, OP_SERVICE_ACTION_IN16};
    private static final int SA_READ_CAPACITY16 = 0x10;

    static final int CBW_SIGNATURE = 0x43425355, CSW_SIGNATURE = 0x53425355;
    static final int CBW_LEN = 31, CSW_LEN = 13;

    /** Max bytes per READ command; same as Linux usb-storage's default (240 x 512). */
    static final int MAX_TRANSFER = 240 * 512;
    static final int CMD_TIMEOUT_MS = 10_000;
    static final int MAX_ATTEMPTS = 4;

    public static final class SenseData
    {
        public final int key, asc, ascq;
        SenseData(int key, int asc, int ascq) { this.key = key; this.asc = asc; this.ascq = ascq; }
        @Override public String toString() { return String.format("sense %X/%02X/%02X", key, asc, ascq); }
    }

    /** Command failed with CHECK CONDITION. */
    public static final class ScsiException extends IOException
    {
        public final SenseData sense;
        ScsiException(String what, SenseData s) { super(what + " failed: " + s); sense = s; }
    }

    /** Transport-level failure; recoverable by reset recovery. */
    private static final class TransportException extends IOException
    {
        TransportException(String m) { super(m); }
    }

    public interface Log
    {
        void log(String msg);
    }

    private final BulkPipe pipe;
    private final Log log;
    private int tag = 1;
    private final byte[] cbw = new byte[CBW_LEN], csw = new byte[CSW_LEN];

    public String vendor = "", product = "", revision = "";
    public boolean removable;
    private int blockSize;
    private long blockCount;
    private byte[] tmp;
    private boolean closed;
    /** Set once the device is known to be unplugged: every later read fails at once. */
    private volatile boolean gone;

    // Statistics, for diagnostics.
    public long commands, resets, retries;

    public static UsbMassStorage open(BulkPipe pipe, Log log) throws IOException
    {
        UsbMassStorage d = new UsbMassStorage(pipe, log);
        try
        {
            d.init();
            return d;
        }
        catch (IOException | RuntimeException e)
        {
            d.close();
            throw e;
        }
    }

    private UsbMassStorage(BulkPipe pipe, Log log)
    {
        this.pipe = pipe;
        this.log = log != null ? log : m -> { };
    }

    public int blockSize() { return blockSize; }

    public long blockCount() { return blockCount; }

    @Override
    public long size() { return blockCount * blockSize; }

    @Override
    public synchronized void close()
    {
        if (!closed)
        {
            closed = true;
            pipe.close();
        }
    }

    // ------------------------------------------------------------------ init

    private void init() throws IOException
    {
        byte[] inq = new byte[36];
        int n = execute("INQUIRY", new byte[]{OP_INQUIRY, 0, 0, 0, 36, 0}, inq, 36, true);
        if (n < 5)
            throw new IOException("INQUIRY returned " + n + " bytes");
        int type = inq[0] & 0x1f;
        if (type != 0)
            throw new IOException("not a direct-access block device (SCSI type " + type + ")");
        removable = (inq[1] & 0x80) != 0;
        if (n >= 36)
        {
            vendor = ascii(inq, 8, 8);
            product = ascii(inq, 16, 16);
            revision = ascii(inq, 32, 4);
        }

        waitReady();
        readCapacity();
        tmp = new byte[MAX_TRANSFER / blockSize * blockSize];
    }

    private void waitReady() throws IOException
    {
        ScsiException last = null;
        for (int i = 0; i < 40; i++)
        {
            try
            {
                execute("TEST UNIT READY", new byte[6], null, 0, false);
                return;
            }
            catch (ScsiException e)
            {
                last = e;
                // 6 = UNIT ATTENTION (media changed / power on), 2 = NOT READY (spinning up).
                if (e.sense.key != 6 && e.sense.key != 2)
                    throw e;
                if (e.sense.key == 2 && e.sense.asc == 0x3A)
                    throw new IOException("no medium in the drive");
                sleep(250);
            }
        }
        throw last;
    }

    private void readCapacity() throws IOException
    {
        byte[] r = new byte[32];
        execute("READ CAPACITY(10)", new byte[]{OP_READ_CAPACITY10, 0, 0, 0, 0, 0, 0, 0, 0, 0}, r, 8, true);
        ByteBuffer b = ByteBuffer.wrap(r);
        long last = b.getInt(0) & 0xffffffffL;
        long bs = b.getInt(4) & 0xffffffffL;
        if (last == 0xffffffffL)
        {
            byte[] c = new byte[16];
            c[0] = (byte) OP_SERVICE_ACTION_IN16;
            c[1] = SA_READ_CAPACITY16;
            c[13] = 32;
            int n = execute("READ CAPACITY(16)", c, r, 32, true);
            if (n < 12)
                throw new IOException("READ CAPACITY(16) returned " + n + " bytes");
            last = b.getLong(0);
            bs = b.getInt(8) & 0xffffffffL;
        }
        if (bs != 512 && bs != 1024 && bs != 2048 && bs != 4096)
            throw new IOException("unsupported block size " + bs);
        if (last < 0 || last >= Long.MAX_VALUE / bs - 1)
            throw new IOException("bad capacity " + last);
        blockSize = (int) bs;
        blockCount = last + 1;
    }

    // ------------------------------------------------------------------ reads

    @Override
    public synchronized void readFully(long off, byte[] buf, int bufOff, int len) throws IOException
    {
        if (closed)
            throw new IOException("device closed");
        if (gone)
            throw new IOException("USB device was disconnected");
        if (len < 0 || bufOff < 0 || bufOff + len > buf.length)
            throw new IndexOutOfBoundsException();
        if (off < 0 || off > size() - len)
            throw new IOException("read outside device: " + off + "+" + len + " > " + size());
        while (len > 0)
        {
            long lba = off / blockSize;
            int skip = (int) (off % blockSize);
            if (skip == 0 && len >= blockSize)
            {
                // Aligned: straight into the caller's buffer.
                int blocks = Math.min(len / blockSize, MAX_TRANSFER / blockSize);
                readBlocks(lba, blocks, buf, bufOff);
                int n = blocks * blockSize;
                off += n; bufOff += n; len -= n;
            }
            else
            {
                int blocks = Math.min((skip + len + blockSize - 1) / blockSize, tmp.length / blockSize);
                readBlocks(lba, blocks, tmp, 0);
                int n = Math.min(len, blocks * blockSize - skip);
                System.arraycopy(tmp, skip, buf, bufOff, n);
                off += n; bufOff += n; len -= n;
            }
        }
    }

    /** Reads {@code count} whole blocks starting at {@code lba}; count*blockSize <= MAX_TRANSFER. */
    private void readBlocks(long lba, int count, byte[] dst, int dstOff) throws IOException
    {
        if (count <= 0 || lba < 0 || lba > blockCount - count)
            throw new IOException("bad block range " + lba + "+" + count);
        byte[] c;
        if (lba + count <= 0xffffffffL && count <= 0xffff)
        {
            c = new byte[10];
            c[0] = (byte) OP_READ10;
            ByteBuffer.wrap(c).putInt(2, (int) lba).putShort(7, (short) count);
        }
        else
        {
            c = new byte[16];
            c[0] = (byte) OP_READ16;
            ByteBuffer.wrap(c).putLong(2, lba).putInt(10, count);
        }
        int len = count * blockSize;
        int n = execute("READ", c, dst, dstOff, len, true);
        if (n != len)
            throw new IOException("short read at LBA " + lba + ": " + n + " of " + len + " bytes");
    }

    // ------------------------------------------------------------------ command layer

    private int execute(String what, byte[] cdb, byte[] data, int len, boolean idempotent) throws IOException
    {
        return execute(what, cdb, data, 0, len, idempotent);
    }

    /**
     * Runs one command with retries. Returns the number of data bytes received.
     * Throws ScsiException on CHECK CONDITION that retrying doesn't fix.
     */
    private int execute(String what, byte[] cdb, byte[] data, int dataOff, int len, boolean idempotent)
            throws IOException
    {
        try
        {
            return executeOnce(what, cdb, data, dataOff, len, idempotent);
        }
        catch (IOException e)
        {
            if (!pipe.isConnected())
                gone = true;
            throw e;
        }
    }

    private int executeOnce(String what, byte[] cdb, byte[] data, int dataOff, int len, boolean idempotent)
            throws IOException
    {
        IOException last = null;
        for (int attempt = 0; attempt < MAX_ATTEMPTS; attempt++)
        {
            if (attempt > 0)
            {
                retries++;
                // Short backoff: lets a glitching device settle, and lets Android notice an
                // unplug (its device list updates a few ms after transfers start failing).
                if (last instanceof TransportException)
                {
                    sleep(100L * attempt);
                    if (!pipe.isConnected())
                        throw new IOException("USB device was disconnected", last);
                }
            }
            try
            {
                int[] got = new int[1];
                int status = transport(cdb, data, dataOff, len, got);
                if (status == 0)
                    return got[0];
                SenseData s = requestSense();
                ScsiException e = new ScsiException(what, s);
                // UNIT ATTENTION is reported once after reset/power-on: just repeat.
                if (s.key == 6 && idempotent)
                {
                    last = e;
                    continue;
                }
                throw e;
            }
            catch (TransportException e)
            {
                last = e;
                log.log(what + ": " + e.getMessage() + ", reset recovery");
                if (!pipe.isConnected())
                    throw new IOException("USB device was disconnected", e);
                resetRecovery();
                if (!idempotent)
                    break;
            }
        }
        if (last instanceof TransportException)
        {
            sleep(300);
            if (!pipe.isConnected())
                throw new IOException("USB device was disconnected", last);
        }
        if (last instanceof ScsiException)
            throw last;
        throw new IOException(what + " failed after " + MAX_ATTEMPTS + " attempts"
                + (last != null ? ": " + last.getMessage() : ""), last);
    }

    private SenseData requestSense() throws IOException
    {
        byte[] s = new byte[18];
        int[] got = new int[1];
        int st = transport(new byte[]{OP_REQUEST_SENSE, 0, 0, 0, 18, 0}, s, 0, 18, got);
        if (st != 0 || got[0] < 8)
            return new SenseData(-1, -1, -1);
        int code = s[0] & 0x7f;
        if (code == 0x72 || code == 0x73)
            return new SenseData(s[1] & 0x0f, s[2] & 0xff, s[3] & 0xff);
        return new SenseData(s[2] & 0x0f, got[0] > 12 ? s[12] & 0xff : 0, got[0] > 13 ? s[13] & 0xff : 0);
    }

    static boolean isAllowed(int opcode)
    {
        for (int op : ALLOWED_OPCODES)
            if (op == opcode)
                return true;
        return false;
    }

    /**
     * One BOT command: CBW out, optional data in, CSW in.
     * Returns the CSW status (0 passed, 1 failed). Throws TransportException for anything that
     * needs reset recovery (bad/missing CSW, phase error, failed CBW).
     */
    private int transport(byte[] cdb, byte[] data, int dataOff, int len, int[] got) throws IOException
    {
        if (cdb.length < 6 || cdb.length > 16)
            throw new IllegalArgumentException("bad CDB length");
        int op = cdb[0] & 0xff;
        if (!isAllowed(op))
            throw new SecurityException(String.format("SCSI opcode 0x%02X is not allowed (read-only)", op));
        commands++;
        int t = tag++;
        ByteBuffer c = ByteBuffer.wrap(cbw).order(ByteOrder.LITTLE_ENDIAN);
        java.util.Arrays.fill(cbw, (byte) 0);
        c.putInt(0, CBW_SIGNATURE).putInt(4, t).putInt(8, len);
        cbw[12] = (byte) (len > 0 ? 0x80 : 0x00); // data-in only
        cbw[13] = 0; // LUN 0
        cbw[14] = (byte) cdb.length;
        System.arraycopy(cdb, 0, cbw, 15, cdb.length);

        if (pipe.bulkOut(cbw, 0, CBW_LEN, CMD_TIMEOUT_MS) != CBW_LEN)
            throw new TransportException("CBW not accepted");

        int received = 0;
        if (len > 0)
        {
            int mps = pipe.maxPacketSize();
            while (received < len)
            {
                int n = pipe.bulkIn(data, dataOff + received, len - received, CMD_TIMEOUT_MS);
                if (n < 0)
                {
                    // Stall (device has less data than asked for) or timeout. Clear and go on
                    // to read the CSW; if the CSW doesn't come, reset recovery handles it.
                    pipe.clearHalt(true);
                    break;
                }
                received += n;
                if (n == 0 || n % mps != 0)
                    break; // short packet ends the data phase
            }
        }
        got[0] = received;

        int n = pipe.bulkIn(csw, 0, CSW_LEN, CMD_TIMEOUT_MS);
        if (n == 0)
            n = pipe.bulkIn(csw, 0, CSW_LEN, CMD_TIMEOUT_MS);
        if (n < 0)
        {
            pipe.clearHalt(true);
            n = pipe.bulkIn(csw, 0, CSW_LEN, CMD_TIMEOUT_MS);
        }
        if (n != CSW_LEN)
            throw new TransportException("no valid CSW (" + n + " bytes)");
        ByteBuffer s = ByteBuffer.wrap(csw).order(ByteOrder.LITTLE_ENDIAN);
        if (s.getInt(0) != CSW_SIGNATURE)
            throw new TransportException("bad CSW signature");
        if (s.getInt(4) != t)
            throw new TransportException("CSW tag mismatch");
        int status = csw[12] & 0xff;
        if (status == 2)
            throw new TransportException("phase error");
        if (status > 2)
            throw new TransportException("bad CSW status " + status);
        int residue = s.getInt(8);
        if (status == 0 && residue > 0 && len - residue < received)
            got[0] = Math.max(0, len - residue);
        return status;
    }

    private void resetRecovery() throws IOException
    {
        resets++;
        boolean ok = pipe.massStorageReset();
        ok &= pipe.clearHalt(true);
        ok &= pipe.clearHalt(false);
        if (!ok)
        {
            if (!pipe.isConnected())
                throw new IOException("USB device was disconnected");
            log.log("reset recovery: device did not accept all requests");
        }
    }

    private static String ascii(byte[] b, int off, int len)
    {
        return new String(b, off, len, StandardCharsets.US_ASCII).replaceAll("[^\\x20-\\x7e]", "?").trim();
    }

    private static void sleep(long ms) throws IOException
    {
        try
        {
            Thread.sleep(ms);
        }
        catch (InterruptedException e)
        {
            Thread.currentThread().interrupt();
            throw new java.io.InterruptedIOException();
        }
    }
}
