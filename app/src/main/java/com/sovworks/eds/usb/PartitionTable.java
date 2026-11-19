package com.sovworks.eds.usb;

import com.sovworks.eds.luks2.Luks2Header;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.zip.CRC32;

/**
 * Read-only GPT / MBR partition table parser.
 *
 * GPT: header and entry-array CRC32s are verified; if the primary copy is damaged the backup
 * at the end of the disk is used (and {@link #warnings} says so). Every partition must lie
 * inside the usable LBA range. MBR: primary partitions only (extended/logical are not
 * followed). A device without a recognised table is returned as one whole-disk "partition",
 * which covers LUKS formatted directly onto the device.
 */
public final class PartitionTable
{
    public enum Scheme { GPT, MBR, NONE }

    public static final String TYPE_LINUX_LUKS = "CA7D7CCB-63ED-4C53-861C-1742536059CC";
    public static final String TYPE_LINUX_FS = "0FC63DAF-8483-4772-8E79-3D69D8477DE4";
    public static final String TYPE_LINUX_LVM = "E6D6D379-F507-44C2-A23C-238F2A3DF928";

    public static final class Partition implements Luks2Header.Source
    {
        public final int number;          // 1-based; 0 = whole device
        public final long offset, length; // bytes
        public final String type;         // GPT type GUID, or "0x83"-style MBR type
        public final String name;         // GPT partition name ("" for MBR)
        public final String uuid;         // GPT unique GUID ("" for MBR)
        private final Luks2Header.Source dev;

        Partition(Luks2Header.Source dev, int number, long offset, long length, String type, String name, String uuid)
        {
            this.dev = dev; this.number = number; this.offset = offset; this.length = length;
            this.type = type; this.name = name; this.uuid = uuid;
        }

        @Override
        public long size() { return length; }

        @Override
        public void readFully(long off, byte[] buf, int bufOff, int len) throws IOException
        {
            if (off < 0 || len < 0 || off > length - len)
                throw new IOException("read outside partition " + number);
            dev.readFully(offset + off, buf, bufOff, len);
        }

        @Override
        public String toString()
        {
            return String.format("#%d offset=%d size=%d type=%s%s", number, offset, length, type,
                    name.isEmpty() ? "" : " name='" + name + "'");
        }
    }

    public final Scheme scheme;
    public final List<Partition> partitions;
    public final List<String> warnings;
    public final String diskGuid;

    private PartitionTable(Scheme s, List<Partition> p, List<String> w, String guid)
    {
        scheme = s; partitions = Collections.unmodifiableList(p); warnings = w; diskGuid = guid;
    }

    public static PartitionTable read(Luks2Header.Source dev, int blockSize) throws IOException
    {
        long blocks = dev.size() / blockSize;
        if (blocks < 2)
            throw new IOException("device too small");
        List<String> warn = new ArrayList<>();
        byte[] mbr = new byte[512];
        dev.readFully(0, mbr, 0, 512);
        boolean hasMbr = (mbr[510] & 0xff) == 0x55 && (mbr[511] & 0xff) == 0xAA;
        boolean protective = false;
        if (hasMbr)
            for (int i = 0; i < 4; i++)
                if ((mbr[446 + 16 * i + 4] & 0xff) == 0xEE)
                    protective = true;

        // GPT: try primary, then backup.
        byte[] lba1 = new byte[blockSize];
        dev.readFully(blockSize, lba1, 0, blockSize);
        boolean gptSig = new String(lba1, 0, 8, StandardCharsets.US_ASCII).equals("EFI PART");
        if (gptSig || protective)
        {
            String err1, err2;
            try
            {
                return gpt(dev, blockSize, blocks, 1, warn);
            }
            catch (IOException e)
            {
                err1 = e.getMessage();
            }
            long alt = blocks - 1;
            try
            {
                PartitionTable t = gpt(dev, blockSize, blocks, alt, warn);
                warn.add(0, "primary GPT is damaged (" + err1 + "); using the backup copy");
                return t;
            }
            catch (IOException e)
            {
                err2 = e.getMessage();
            }
            throw new IOException("GPT is damaged: primary: " + err1 + "; backup: " + err2);
        }
        if (hasMbr)
        {
            List<Partition> parts = mbr(dev, mbr, blockSize, blocks, warn);
            if (parts != null)
                return new PartitionTable(Scheme.MBR, parts, warn, "");
        }
        List<Partition> whole = new ArrayList<>();
        whole.add(new Partition(dev, 0, 0, dev.size(), "", "", ""));
        return new PartitionTable(Scheme.NONE, whole, warn, "");
    }

    private static PartitionTable gpt(Luks2Header.Source dev, int bs, long blocks, long hdrLba, List<String> warn)
            throws IOException
    {
        byte[] h = new byte[bs];
        dev.readFully(hdrLba * bs, h, 0, bs);
        ByteBuffer b = ByteBuffer.wrap(h).order(ByteOrder.LITTLE_ENDIAN);
        if (!new String(h, 0, 8, StandardCharsets.US_ASCII).equals("EFI PART"))
            throw new IOException("no GPT signature at LBA " + hdrLba);
        int hdrSize = b.getInt(12);
        if (hdrSize < 92 || hdrSize > bs)
            throw new IOException("bad header size " + hdrSize);
        int crc = b.getInt(16);
        byte[] copy = h.clone();
        ByteBuffer.wrap(copy).order(ByteOrder.LITTLE_ENDIAN).putInt(16, 0);
        if (crc32(copy, 0, hdrSize) != crc)
            throw new IOException("header CRC mismatch");
        long myLba = b.getLong(24), firstUsable = b.getLong(40), lastUsable = b.getLong(48);
        long entriesLba = b.getLong(72);
        int count = b.getInt(80), esz = b.getInt(84), entriesCrc = b.getInt(88);
        if (myLba != hdrLba)
            throw new IOException("header LBA field " + myLba + " != " + hdrLba);
        if (firstUsable < 2 || lastUsable >= blocks || firstUsable > lastUsable)
            throw new IOException("bad usable range " + firstUsable + ".." + lastUsable);
        if (esz < 128 || esz % 8 != 0 || count < 0 || (long) count * esz > 4 << 20)
            throw new IOException("bad entry array " + count + " x " + esz);
        long arrBytes = (long) count * esz;
        long arrBlocks = (arrBytes + bs - 1) / bs;
        if (entriesLba < 2 || entriesLba > blocks - arrBlocks)
            throw new IOException("entry array outside the device");
        byte[] arr = new byte[(int) arrBytes];
        dev.readFully(entriesLba * bs, arr, 0, arr.length);
        if (crc32(arr, 0, arr.length) != entriesCrc)
            throw new IOException("entry array CRC mismatch");

        List<Partition> parts = new ArrayList<>();
        ByteBuffer e = ByteBuffer.wrap(arr).order(ByteOrder.LITTLE_ENDIAN);
        for (int i = 0; i < count; i++)
        {
            int o = i * esz;
            String type = guid(arr, o);
            if (type.equals("00000000-0000-0000-0000-000000000000"))
                continue;
            long first = e.getLong(o + 32), last = e.getLong(o + 40);
            if (first < firstUsable || last > lastUsable || first > last)
            {
                warn.add("partition " + (i + 1) + " lies outside the usable area; ignored");
                continue;
            }
            int nameEnd = o + 56;
            while (nameEnd + 1 < o + 128 && (arr[nameEnd] != 0 || arr[nameEnd + 1] != 0))
                nameEnd += 2;
            String name = new String(arr, o + 56, nameEnd - (o + 56), StandardCharsets.UTF_16LE);
            parts.add(new Partition(dev, i + 1, first * bs, (last - first + 1) * bs, type, name, guid(arr, o + 16)));
        }
        return new PartitionTable(Scheme.GPT, parts, warn, guid(h, 56));
    }

    private static List<Partition> mbr(Luks2Header.Source dev, byte[] mbr, int bs, long blocks, List<String> warn)
    {
        ByteBuffer b = ByteBuffer.wrap(mbr).order(ByteOrder.LITTLE_ENDIAN);
        List<Partition> parts = new ArrayList<>();
        boolean any = false;
        for (int i = 0; i < 4; i++)
        {
            int o = 446 + 16 * i;
            int status = mbr[o] & 0xff, type = mbr[o + 4] & 0xff;
            long start = b.getInt(o + 8) & 0xffffffffL, count = b.getInt(o + 12) & 0xffffffffL;
            if (type == 0)
                continue;
            if (status != 0 && status != 0x80)
                return null; // not a partition table (e.g. a FAT boot sector)
            any = true;
            if (type == 0x05 || type == 0x0F || type == 0x85)
            {
                warn.add("extended partition " + (i + 1) + " is not supported");
                continue;
            }
            if (start == 0 || count == 0 || start + count > blocks)
            {
                warn.add("MBR partition " + (i + 1) + " lies outside the device; ignored");
                continue;
            }
            parts.add(new Partition(dev, i + 1, start * bs, count * bs, String.format("0x%02X", type), "", ""));
        }
        return any ? parts : null;
    }

    static int crc32(byte[] b, int off, int len)
    {
        CRC32 c = new CRC32();
        c.update(b, off, len);
        return (int) c.getValue();
    }

    static String guid(byte[] b, int o)
    {
        ByteBuffer g = ByteBuffer.wrap(b, o, 16).order(ByteOrder.LITTLE_ENDIAN);
        int d1 = g.getInt(o);
        short d2 = g.getShort(o + 4), d3 = g.getShort(o + 6);
        StringBuilder s = new StringBuilder(String.format("%08X-%04X-%04X-", d1, d2 & 0xffff, d3 & 0xffff));
        for (int i = 8; i < 16; i++)
        {
            if (i == 10)
                s.append('-');
            s.append(String.format("%02X", b[o + i] & 0xff));
        }
        return s.toString();
    }
}
