package com.sovworks.eds.usb;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import java.util.zip.CRC32;

/**
 * Desktop tests for UsbMassStorage (BOT/SCSI) against a simulated device with fault injection,
 * and for PartitionTable against synthetic GPT/MBR images.
 */
public class UsbSimTest
{
    enum Fault { NONE, CBW_FAIL, DATA_TIMEOUT, BAD_TAG, PHASE_ERROR, UNIT_ATTENTION, ZLP_BEFORE_CSW, DATA_STALL_CSW_OK, SHORT_GOOD }

    /** Simulated BOT device backed by an image. Records everything the host sends. */
    static final class SimDevice implements BulkPipe
    {
        final byte[] img; final int bs; final int mps = 1024; final int maxChunk;
        final List<byte[]> sentOut = new ArrayList<>();
        final List<Fault> faults = new ArrayList<>(); // per command, consumed in order
        boolean connected = true, needReset, unitAttentionPending;
        int resets, cmds;
        // pending response
        byte[] data; int dataPos; byte[] csw; boolean stalled, zlp;
        int senseKey;

        SimDevice(byte[] img, int bs, int maxChunk) { this.img = img; this.bs = bs; this.maxChunk = maxChunk; }

        public int maxPacketSize() { return mps; }

        public int bulkOut(byte[] b, int off, int len, int t)
        {
            sentOut.add(Arrays.copyOfRange(b, off, off + len));
            if (!connected || needReset) return -1;
            Fault f = faults.isEmpty() ? Fault.NONE : faults.remove(0);
            cmds++;
            if (f == Fault.CBW_FAIL) { needReset = true; return -1; }
            if (len != 31) throw new AssertionError("non-CBW bulk OUT of " + len + " bytes");
            ByteBuffer c = ByteBuffer.wrap(b, off, len).order(ByteOrder.LITTLE_ENDIAN);
            if (c.getInt(off) != UsbMassStorage.CBW_SIGNATURE) throw new AssertionError("bad CBW sig");
            int tag = c.getInt(off + 4), dlen = c.getInt(off + 8), flags = b[off + 12] & 0xff;
            if (dlen > 0 && flags != 0x80) throw new AssertionError("data-OUT CBW");
            byte[] cdb = Arrays.copyOfRange(b, off + 15, off + 15 + b[off + 14]);
            int op = cdb[0] & 0xff;
            if (!UsbMassStorage.isAllowed(op)) throw new AssertionError("disallowed opcode " + op);
            int status = 0;
            byte[] resp = new byte[0];
            if (f == Fault.UNIT_ATTENTION) unitAttentionPending = true;
            if (unitAttentionPending && op != UsbMassStorage.OP_REQUEST_SENSE && op != UsbMassStorage.OP_INQUIRY)
            {
                unitAttentionPending = false; senseKey = 6; status = 1;
            }
            else switch (op)
            {
                case 0x12: resp = new byte[36]; System.arraycopy("SIMVENDRSimulated Disk  0001".getBytes(), 0, resp, 8, 28); resp[1] = (byte) 0x80; break;
                case 0x00: break;
                case 0x03: resp = new byte[18]; resp[0] = 0x70; resp[2] = (byte) senseKey; resp[12] = 0x28; senseKey = 0; break;
                case 0x25: resp = ByteBuffer.allocate(8).putInt(img.length / bs - 1).putInt(bs).array(); break;
                case 0x28: case 0x88:
                {
                    ByteBuffer cb = ByteBuffer.wrap(cdb);
                    long lba = op == 0x28 ? cb.getInt(2) & 0xffffffffL : cb.getLong(2);
                    int n = op == 0x28 ? cb.getShort(7) & 0xffff : cb.getInt(10);
                    if ((lba + n) * bs > img.length) { status = 1; senseKey = 5; break; }
                    resp = Arrays.copyOfRange(img, (int) (lba * bs), (int) ((lba + n) * bs));
                    break;
                }
                default: throw new AssertionError("unexpected opcode " + op);
            }
            int deliver = Math.min(dlen, resp.length);
            int residue = dlen - deliver;
            if (f == Fault.SHORT_GOOD && deliver > 512) { deliver -= 512; residue = 0; }
            data = Arrays.copyOf(resp, deliver); dataPos = 0;
            stalled = (f == Fault.DATA_STALL_CSW_OK) || (deliver < dlen && deliver % mps == 0);
            if (f == Fault.DATA_STALL_CSW_OK) { data = Arrays.copyOf(resp, deliver / 2 / mps * mps); residue = dlen - data.length; status = 1; senseKey = 3; }
            zlp = f == Fault.ZLP_BEFORE_CSW;
            csw = ByteBuffer.allocate(13).order(ByteOrder.LITTLE_ENDIAN).putInt(UsbMassStorage.CSW_SIGNATURE)
                    .putInt(f == Fault.BAD_TAG ? tag + 7 : tag).putInt(residue)
                    .put((byte) (f == Fault.PHASE_ERROR ? 2 : status)).array();
            if (f == Fault.DATA_TIMEOUT) { data = Arrays.copyOf(resp, Math.min(resp.length, mps)); csw = null; needReset = true; }
            return 31;
        }

        public int bulkIn(byte[] b, int off, int len, int t)
        {
            if (!connected) return -1;
            if (data != null && dataPos < data.length)
            {
                int n = Math.min(Math.min(len, data.length - dataPos), maxChunk);
                if (n < len && n % mps != 0 && dataPos + n < data.length) n = n / mps * mps;
                System.arraycopy(data, dataPos, b, off, n); dataPos += n;
                return n;
            }
            if (stalled) return -1; // stays halted until cleared
            if (zlp) { zlp = false; return 0; }
            if (csw == null) return -1;
            if (len < 13) return -1; // overflow
            System.arraycopy(csw, 0, b, off, 13);
            csw = null; data = null;
            return 13;
        }

        public boolean clearHalt(boolean in) { if (!connected) return false; if (in) stalled = false; return true; }
        public boolean massStorageReset() { if (!connected) return false; resets++; needReset = false; data = null; csw = null; stalled = false; return true; }
        public boolean isConnected() { return connected; }
        public void close() { }
    }

    static int failures = 0;
    static void check(boolean ok, String what) { System.out.println((ok ? "  ok   " : "  FAIL ") + what); if (!ok) failures++; }

    public static void main(String[] a) throws Exception
    {
        Random rnd = new Random(42);
        for (int bs : new int[]{512, 4096})
        {
            System.out.println("== BOT, block size " + bs);
            byte[] img = new byte[bs * 4096];
            rnd.nextBytes(img);
            byte[] orig = img.clone();

            SimDevice sim = new SimDevice(img, bs, 16384);
            sim.faults.add(Fault.NONE); sim.faults.add(Fault.UNIT_ATTENTION); // TUR after power-on
            UsbMassStorage d = UsbMassStorage.open(sim, m -> { });
            check(d.size() == img.length && d.blockSize() == bs, "capacity " + d.size());
            check(d.vendor.equals("SIMVENDR"), "inquiry vendor '" + d.vendor + "'");

            // random reads, all alignments, crossing the 120 KiB command limit
            boolean same = true;
            for (int i = 0; i < 300; i++)
            {
                int len = rnd.nextInt(i % 10 == 0 ? 400_000 : 9000) + 1;
                long off = (long) rnd.nextInt(img.length - len);
                byte[] buf = new byte[len];
                d.readFully(off, buf, 0, len);
                same &= Arrays.equals(buf, Arrays.copyOfRange(img, (int) off, (int) off + len));
            }
            check(same, "300 random unaligned reads match the image");

            for (Fault f : new Fault[]{Fault.CBW_FAIL, Fault.DATA_TIMEOUT, Fault.BAD_TAG, Fault.PHASE_ERROR,
                    Fault.UNIT_ATTENTION, Fault.ZLP_BEFORE_CSW})
            {
                sim.faults.add(f);
                byte[] buf = new byte[3 * bs + 100];
                long off = 5L * bs + 17;
                boolean ok;
                try
                {
                    d.readFully(off, buf, 0, buf.length);
                    ok = Arrays.equals(buf, Arrays.copyOfRange(img, (int) off, (int) off + buf.length));
                }
                catch (IOException e) { ok = false; System.out.println("    " + e); }
                check(ok, "recovers from " + f + " (resets so far " + d.resets + ")");
            }

            sim.faults.add(Fault.DATA_STALL_CSW_OK);
            try { d.readFully(0, new byte[bs * 64], 0, bs * 64); check(false, "medium error is reported"); }
            catch (UsbMassStorage.ScsiException e) { check(e.sense.key == 3, "medium error reported as " + e.sense); }

            sim.faults.add(Fault.SHORT_GOOD);
            try { d.readFully(0, new byte[bs * 8], 0, bs * 8); check(false, "short read with good status detected"); }
            catch (IOException e) { check(true, "short read with good status detected: " + e.getMessage()); }

            // device keeps working after all that
            byte[] buf = new byte[bs * 300];
            d.readFully(bs * 100L, buf, 0, buf.length);
            check(Arrays.equals(buf, Arrays.copyOfRange(img, bs * 100, bs * 400)), "reads fine after faults");

            try { d.readFully(img.length - 10, new byte[20], 0, 20); check(false, "read past end refused"); }
            catch (IOException e) { check(true, "read past end refused"); }

            // every OUT transfer was a 31-byte CBW with an allowed opcode and no data-out
            boolean allCbw = true;
            for (byte[] o : sim.sentOut)
                allCbw &= o.length == 31 && UsbMassStorage.isAllowed(o[15] & 0xff) && ((o[12] & 0xff) == 0x80 || o[12] == 0);
            check(allCbw, sim.sentOut.size() + " OUT transfers, all read-only CBWs");
            check(Arrays.equals(img, orig), "image unchanged");

            // unplug
            sim.connected = false;
            long t0 = System.nanoTime();
            try { d.readFully(0, new byte[bs], 0, bs); check(false, "unplug reported"); }
            catch (IOException e) { check(e.getMessage().contains("disconnected"), "unplug reported: " + e.getMessage()); }
            check((System.nanoTime() - t0) / 1e6 < 1000, "unplug detected quickly");
        }
        gptTests();
        System.out.println(failures == 0 ? "ALL PASSED" : failures + " FAILED");
        System.exit(failures == 0 ? 0 : 1);
    }

    // ---------------------------------------------------------------- partition tables

    static final class Mem implements com.sovworks.eds.luks2.Luks2Header.Source
    {
        final byte[] b; Mem(byte[] b) { this.b = b; }
        public long size() { return b.length; }
        public void readFully(long off, byte[] buf, int o, int l) throws IOException
        {
            if (off < 0 || off + l > b.length) throw new IOException("oob");
            System.arraycopy(b, (int) off, buf, o, l);
        }
    }

    static byte[] guidBytes(String g)
    {
        String h = g.replace("-", "");
        byte[] r = new byte[16];
        for (int i = 0; i < 16; i++) r[i] = (byte) Integer.parseInt(h.substring(i * 2, i * 2 + 2), 16);
        // mixed-endian first three fields
        byte[] o = r.clone();
        r[0] = o[3]; r[1] = o[2]; r[2] = o[1]; r[3] = o[0]; r[4] = o[5]; r[5] = o[4]; r[6] = o[7]; r[7] = o[6];
        return r;
    }

    static int crc(byte[] b, int off, int len) { CRC32 c = new CRC32(); c.update(b, off, len); return (int) c.getValue(); }

    /** Builds a GPT disk with the given partitions {firstLba, lastLba}. */
    static byte[] gptImage(int bs, long blocks, long[][] parts)
    {
        byte[] img = new byte[(int) (bs * blocks)];
        // protective MBR
        img[446 + 4] = (byte) 0xEE; img[510] = 0x55; img[511] = (byte) 0xAA;
        int n = 128, esz = 128;
        byte[] arr = new byte[n * esz];
        for (int i = 0; i < parts.length; i++)
        {
            ByteBuffer e = ByteBuffer.wrap(arr, i * esz, esz).order(ByteOrder.LITTLE_ENDIAN);
            System.arraycopy(guidBytes(PartitionTable.TYPE_LINUX_LUKS), 0, arr, i * esz, 16);
            System.arraycopy(guidBytes("11111111-2222-3333-4444-55555555555" + i), 0, arr, i * esz + 16, 16);
            e.putLong(i * esz + 32, parts[i][0]).putLong(i * esz + 40, parts[i][1]);
            byte[] name = ("part" + i).getBytes(StandardCharsets.UTF_16LE);
            System.arraycopy(name, 0, arr, i * esz + 56, name.length);
        }
        long arrBlocks = (arr.length + bs - 1) / bs;
        long firstUsable = 2 + arrBlocks, lastUsable = blocks - 2 - arrBlocks;
        writeHdr(img, bs, 1, blocks - 1, 2, firstUsable, lastUsable, arr, n, esz);
        writeHdr(img, bs, blocks - 1, 1, blocks - 1 - arrBlocks, firstUsable, lastUsable, arr, n, esz);
        return img;
    }

    static void writeHdr(byte[] img, int bs, long my, long alt, long entries, long fu, long lu, byte[] arr, int n, int esz)
    {
        System.arraycopy(arr, 0, img, (int) (entries * bs), arr.length);
        ByteBuffer h = ByteBuffer.wrap(img, (int) (my * bs), 92).order(ByteOrder.LITTLE_ENDIAN);
        int o = (int) (my * bs);
        System.arraycopy("EFI PART".getBytes(), 0, img, o, 8);
        h.putInt(o + 8, 0x00010000).putInt(o + 12, 92).putInt(o + 16, 0).putLong(o + 24, my).putLong(o + 32, alt)
                .putLong(o + 40, fu).putLong(o + 48, lu).putLong(o + 72, entries).putInt(o + 80, n).putInt(o + 84, esz)
                .putInt(o + 88, crc(arr, 0, arr.length));
        h.putInt(o + 16, crc(img, o, 92));
    }

    static void gptTests() throws IOException
    {
        for (int bs : new int[]{512, 4096})
        {
            System.out.println("== partition tables, block size " + bs);
            long blocks = 2048;
            long[][] parts = {{40, 99}, {100, 1999}};
            byte[] img = gptImage(bs, blocks, parts);
            PartitionTable t = PartitionTable.read(new Mem(img), bs);
            check(t.scheme == PartitionTable.Scheme.GPT && t.partitions.size() == 2 && t.warnings.isEmpty(), "GPT parsed: " + t.partitions);
            PartitionTable.Partition p = t.partitions.get(1);
            check(p.offset == 100L * bs && p.length == 1900L * bs && p.type.equals(PartitionTable.TYPE_LINUX_LUKS)
                    && p.name.equals("part1"), "partition 2 geometry, type and name");
            try { p.readFully(p.length - 4, new byte[8], 0, 8); check(false, "partition bounds enforced"); }
            catch (IOException e) { check(true, "partition bounds enforced"); }

            byte[] c1 = img.clone(); c1[bs + 40] ^= 1; // primary header first_usable bit flip
            t = PartitionTable.read(new Mem(c1), bs);
            check(t.partitions.size() == 2 && !t.warnings.isEmpty() && t.warnings.get(0).contains("backup"),
                    "damaged primary header -> backup used: " + t.warnings);

            byte[] c2 = img.clone(); c2[2 * bs + 33] ^= 1; // primary entry array
            t = PartitionTable.read(new Mem(c2), bs);
            check(t.partitions.size() == 2 && t.warnings.get(0).contains("entry array CRC"), "damaged primary entries -> backup used");

            byte[] c3 = img.clone(); c3[bs + 40] ^= 1; c3[(int) ((blocks - 1) * bs) + 40] ^= 1;
            try { PartitionTable.read(new Mem(c3), bs); check(false, "both copies damaged -> error"); }
            catch (IOException e) { check(e.getMessage().contains("damaged"), "both copies damaged -> error: " + e.getMessage()); }

            byte[] c4 = gptImage(bs, blocks, new long[][]{{40, 99}, {100, 5000}});
            t = PartitionTable.read(new Mem(c4), bs);
            check(t.partitions.size() == 1 && t.warnings.size() == 1, "partition past the end ignored: " + t.warnings);

            // MBR only
            byte[] m = new byte[bs * 256];
            m[510] = 0x55; m[511] = (byte) 0xAA;
            ByteBuffer mb = ByteBuffer.wrap(m).order(ByteOrder.LITTLE_ENDIAN);
            m[446 + 4] = (byte) 0x83; mb.putInt(446 + 8, 8).putInt(446 + 12, 100);
            m[462 + 4] = 0x05; mb.putInt(462 + 8, 120).putInt(462 + 12, 10);
            m[478 + 4] = (byte) 0x83; mb.putInt(478 + 8, 200).putInt(478 + 12, 500);
            t = PartitionTable.read(new Mem(m), bs);
            check(t.scheme == PartitionTable.Scheme.MBR && t.partitions.size() == 1 && t.warnings.size() == 2,
                    "MBR: 1 partition, extended + out-of-range warned: " + t.warnings);

            // no table (LUKS directly on the device)
            byte[] raw = new byte[bs * 64];
            System.arraycopy(new byte[]{'L', 'U', 'K', 'S', (byte) 0xBA, (byte) 0xBE}, 0, raw, 0, 6);
            t = PartitionTable.read(new Mem(raw), bs);
            check(t.scheme == PartitionTable.Scheme.NONE && t.partitions.size() == 1 && t.partitions.get(0).length == raw.length,
                    "no table -> whole device");
        }
    }
}
