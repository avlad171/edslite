import com.sovworks.eds.luks2.Luks2Header;
import com.sovworks.eds.luks2.Luks2Volume;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.io.RandomAccessFile;
import java.util.Arrays;

/** Usage: Luks2Unlock <device> <devSize> <partOffset> <partSize> <passphraseFile>. Read-only. */
public class Luks2Unlock
{
    public static void main(String[] a) throws Exception
    {
        try (RandomAccessFile f = new RandomAccessFile(a[0], "r"))
        {
            Luks2Info.Part p = new Luks2Info.Part(f, Long.parseLong(a[2]), Long.parseLong(a[3]));
            byte[] pw = Files.readAllBytes(Paths.get(a[4]));
            Luks2Header h = Luks2Header.read(p);
            long t0 = System.nanoTime();
            try (Luks2Volume v = Luks2Volume.unlock(p, h, pw, (id, kdf) -> System.out.println("trying keyslot " + id + " (" + kdf + ")")))
            {
                Arrays.fill(pw, (byte) 0);
                System.out.printf("unlocked in %.1fs; payload %.1f GB, sector %d%n", (System.nanoTime() - t0) / 1e9, v.size() / 1e9, v.sectorSize());
                byte[] b = new byte[4096];
                v.read(0, b, 0, b.length);
                String lbl = new String(b, 512, 8, "ASCII");
                System.out.println("offset 512: " + (lbl.equals("LABELONE") ? "LVM2 PV label (" + new String(b, 512 + 24, 8, "ASCII") + ")" : "no LVM label"));
                System.out.println("ext magic at 1080: " + ((b[1080] & 0xff) == 0x53 && (b[1081] & 0xff) == 0xEF));
                System.out.println("btrfs magic at 64K+64: " + checkBtrfs(v));
            }
        }
    }

    static boolean checkBtrfs(Luks2Volume v) throws Exception
    {
        byte[] b = new byte[8];
        v.read(65536 + 64, b, 0, 8);
        return new String(b, "ASCII").equals("_BHRfS_M");
    }
}
