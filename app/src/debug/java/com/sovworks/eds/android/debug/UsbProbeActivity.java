package com.sovworks.eds.android.debug;

import android.app.Activity;
import android.content.Context;
import android.graphics.Typeface;
import android.hardware.usb.UsbManager;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.SystemClock;
import android.text.Editable;
import android.text.InputType;
import android.util.Log;
import android.view.View;
import android.view.inputmethod.EditorInfo;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import com.sovworks.eds.fs.Path;
import com.sovworks.eds.fs.ext4.Ext4FS;
import com.sovworks.eds.luks2.Luks2Exception;
import com.sovworks.eds.luks2.Luks2Header;
import com.sovworks.eds.luks2.Luks2Volume;
import com.sovworks.eds.luks2.Lvm2;
import com.sovworks.eds.luks2.SourceIO;
import com.sovworks.eds.usb.AndroidBulkPipe;
import com.sovworks.eds.usb.PartitionTable;
import com.sovworks.eds.usb.UsbMassStorage;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * DEBUG BUILDS ONLY. Read-only probe of an attached USB stick: identify, capacity, partition
 * table, LUKS2 header structure, optional sequential read speed test; then, with a passphrase
 * typed on the device, unlock LUKS2 -> LVM2 -> ext4 and list the top-level directory.
 *
 * Never logs the passphrase, salts, digests or key material. Logs file names of the top level.
 *
 *   adb shell am start --user 10 -n com.sovworks.edslite/com.sovworks.eds.android.debug.UsbProbeActivity
 *       [--ei readMiB 64]
 * Output: on screen and in logcat, tag "EdsUsbProbe".
 */
public class UsbProbeActivity extends Activity
{
    private static final String TAG = "EdsUsbProbe";
    private final Handler ui = new Handler(Looper.getMainLooper());
    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private TextView text;
    private EditText pass;
    private Button unlock;

    // Accessed on the worker thread only.
    private UsbMassStorage dev;
    private PartitionTable.Partition luksPart;
    private Luks2Header luksHdr;

    @Override
    protected void onCreate(Bundle b)
    {
        super.onCreate(b);
        setTitle("EDS USB probe (read-only)");
        int pad = (int) (12 * getResources().getDisplayMetrics().density);

        pass = new EditText(this);
        pass.setHint("LUKS passphrase");
        pass.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
        pass.setImeOptions(EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING | EditorInfo.IME_ACTION_DONE);
        pass.setImportantForAutofill(View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS);
        pass.setLongClickable(false);
        if (Build.VERSION.SDK_INT >= 34)
            pass.setAccessibilityDataSensitive(View.ACCESSIBILITY_DATA_SENSITIVE_YES);
        unlock = new Button(this);
        unlock.setText("Unlock");
        unlock.setEnabled(false);
        unlock.setOnClickListener(v -> onUnlock());
        LinearLayout row = new LinearLayout(this);
        row.addView(pass, new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1));
        row.addView(unlock);

        text = new TextView(this);
        text.setTypeface(Typeface.MONOSPACE);
        text.setTextSize(12);
        text.setPadding(pad, pad, pad, pad);
        ScrollView sv = new ScrollView(this);
        sv.addView(text);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setFitsSystemWindows(true);
        root.setPadding(pad, 0, pad, 0);
        root.addView(row);
        root.addView(sv, new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, 0, 1));
        setContentView(root);

        UsbManager um = (UsbManager) getSystemService(Context.USB_SERVICE);
        List<AndroidBulkPipe.Candidate> cs = AndroidBulkPipe.find(um);
        out("USB devices attached: " + um.getDeviceList().size() + ", mass-storage BOT: " + cs.size());
        if (cs.isEmpty())
        {
            out("No USB mass-storage device found.");
            return;
        }
        AndroidBulkPipe.Candidate c = cs.get(0);
        out("Using " + c.describe());
        int readMiB = getIntent().getIntExtra("readMiB", 0);
        AndroidBulkPipe.requestPermission(this, c.device, granted -> {
            out("Permission " + (granted ? "granted" : "DENIED"));
            if (granted)
                worker.execute(() -> probe(um, c, readMiB));
        });
    }

    @Override
    protected void onDestroy()
    {
        worker.execute(() -> {
            if (dev != null)
                dev.close();
        });
        worker.shutdown();
        super.onDestroy();
    }

    private void probe(UsbManager um, AndroidBulkPipe.Candidate c, int readMiB)
    {
        long t0 = SystemClock.elapsedRealtime();
        try
        {
            dev = UsbMassStorage.open(AndroidBulkPipe.open(um, c), m -> out("  [usb] " + m));
            out(String.format("INQUIRY: '%s' '%s' rev '%s'%s", dev.vendor, dev.product, dev.revision,
                    dev.removable ? " (removable)" : ""));
            out(String.format("Capacity: %d blocks x %d B = %.2f GB  (open took %d ms)", dev.blockCount(),
                    dev.blockSize(), dev.size() / 1e9, SystemClock.elapsedRealtime() - t0));

            PartitionTable pt = PartitionTable.read(dev, dev.blockSize());
            out("Partition table: " + pt.scheme + (pt.diskGuid.isEmpty() ? "" : " disk " + pt.diskGuid));
            for (String w : pt.warnings)
                out("  WARNING: " + w);
            for (PartitionTable.Partition p : pt.partitions)
            {
                out(String.format("  part %d: offset %d, %.2f GB, type %s%s%s", p.number, p.offset, p.length / 1e9,
                        p.type, typeName(p.type), p.name.isEmpty() ? "" : ", name '" + p.name + "'"));
                Luks2Header h = inspect(p);
                if (h != null && luksPart == null)
                {
                    luksPart = p;
                    luksHdr = h;
                }
            }

            if (readMiB > 0)
            {
                byte[] buf = new byte[1 << 20];
                long n = Math.min((long) readMiB << 20, dev.size() / buf.length * buf.length);
                long s = SystemClock.elapsedRealtime();
                for (long off = 0; off < n; off += buf.length)
                    dev.readFully(off, buf, 0, buf.length);
                long ms = Math.max(1, SystemClock.elapsedRealtime() - s);
                out(String.format("Sequential read: %d MiB in %d ms = %.1f MB/s", n >> 20, ms, n / 1e3 / ms));
            }
            out(String.format("Probe done. commands=%d retries=%d resets=%d", dev.commands, dev.retries, dev.resets));
            if (luksPart != null)
            {
                out("Ready: type the passphrase for partition " + luksPart.number + " and tap Unlock.");
                ui.post(() -> unlock.setEnabled(true));
            }
        }
        catch (Throwable e)
        {
            Log.e(TAG, "probe failed", e);
            out("FAILED: " + e);
        }
    }

    private void onUnlock()
    {
        Editable e = pass.getText();
        char[] chars = new char[e.length()];
        e.getChars(0, chars.length, chars, 0);
        e.clear();
        unlock.setEnabled(false);
        ByteBuffer bb = StandardCharsets.UTF_8.encode(CharBuffer.wrap(chars));
        Arrays.fill(chars, '\0');
        byte[] pw = new byte[bb.remaining()];
        bb.get(pw);
        Arrays.fill(bb.array(), (byte) 0);
        worker.execute(() -> {
            try
            {
                unlockAndList(pw);
            }
            finally
            {
                Arrays.fill(pw, (byte) 0);
                ui.post(() -> unlock.setEnabled(true));
            }
        });
    }

    private void unlockAndList(byte[] pw)
    {
        long c0 = dev.commands;
        long t0 = SystemClock.elapsedRealtime();
        out("Unlocking partition " + luksPart.number + " ...");
        Luks2Volume vol;
        try
        {
            vol = Luks2Volume.unlock(luksPart, luksHdr, pw,
                    (id, kdf) -> out("  trying keyslot " + id + " (" + kdf + ")"));
        }
        catch (Luks2Exception ex)
        {
            out(String.format("  %s  (%d ms)", ex.getMessage(), SystemClock.elapsedRealtime() - t0));
            return;
        }
        catch (Throwable ex)
        {
            Log.e(TAG, "unlock failed", ex);
            out("  UNLOCK FAILED: " + ex);
            return;
        }
        finally
        {
            Arrays.fill(pw, (byte) 0);
        }
        out(String.format("  Unlocked in %d ms; decrypted size %.2f GB", SystemClock.elapsedRealtime() - t0,
                vol.size() / 1e9));
        try
        {
            if (Lvm2.hasLabel(vol))
            {
                Lvm2 lvm = Lvm2.read(vol);
                out("  LVM volume group '" + lvm.vgName + "' seqno " + lvm.seqno);
                lvm.unsupported.forEach((n, why) -> out("    LV " + n + " unsupported: " + why));
                for (Lvm2.LogicalVolume lv : lvm.volumes.values())
                {
                    out(String.format("    LV %s: %.2f GB, %d segment(s)", lv.name, lv.size / 1e9, lv.segsCount()));
                    listExt4(lv.name, new SourceIO(lv));
                }
            }
            else
                listExt4("(no LVM)", new SourceIO(vol));
        }
        catch (Throwable ex)
        {
            Log.e(TAG, "listing failed", ex);
            out("  FAILED: " + ex);
        }
        finally
        {
            vol.close();
            out(String.format("Closed; key wiped. USB commands used: %d, retries=%d resets=%d",
                    dev.commands - c0, dev.retries, dev.resets));
        }
    }

    private void listExt4(String name, SourceIO io) throws Exception
    {
        if (!Ext4FS.isExt4Image(io))
        {
            out("      [" + name + "] not ext2/3/4");
            return;
        }
        long t0 = SystemClock.elapsedRealtime();
        Ext4FS fs;
        try
        {
            fs = new Ext4FS(io);
        }
        catch (Exception e)
        {
            out("      [" + name + "] " + e.getMessage());
            return;
        }
        try
        {
            long mountMs = SystemClock.elapsedRealtime() - t0;
            Path root = fs.getRootPath();
            com.sovworks.eds.fs.Directory d = root.getDirectory();
            out(String.format("      [%s] ext4 mounted read-only in %d ms; %.1f GB total, %.1f GB free", name, mountMs,
                    d.getTotalSpace() / 1e9, d.getFreeSpace() / 1e9));
            List<String> names = new ArrayList<>();
            try (com.sovworks.eds.fs.Directory.Contents cs = d.list())
            {
                for (Path p : cs)
                {
                    String n = p.getPathString(); n = n.substring(n.lastIndexOf('/') + 1);
                    names.add(p.isDirectory() ? n + "/" : n);
                }
            }
            Collections.sort(names);
            out("      / : " + names.size() + " entries (listed in " + (SystemClock.elapsedRealtime() - t0 - mountMs) + " ms)");
            StringBuilder sb = new StringBuilder();
            for (String n : names)
            {
                if (sb.length() + n.length() > 70)
                {
                    out("        " + sb);
                    sb.setLength(0);
                }
                sb.append(n).append("  ");
            }
            if (sb.length() > 0)
                out("        " + sb);
        }
        finally
        {
            fs.close(true);
        }
    }

    private Luks2Header inspect(PartitionTable.Partition p)
    {
        try
        {
            if (!Luks2Header.hasLuks2Magic(p))
            {
                out("    not LUKS2");
                return null;
            }
            Luks2Header h = Luks2Header.read(p);
            out(String.format("    LUKS2 label='%s' hdr_size=%d seqid=%d copies in sync: %s%s", h.label, h.hdrSize,
                    h.seqid, !h.copiesOutOfSync, h.usedSecondary ? " (using secondary)" : ""));
            for (Luks2Header.Keyslot k : h.keyslots)
                out(String.format("    keyslot %s: kdf %s%s, key %d B, prio %d", k.id, k.kdf.type,
                        k.kdf.type.equals("pbkdf2") ? " it=" + k.kdf.iterations
                                : " t=" + k.kdf.time + " m=" + k.kdf.memoryKiB + "KiB p=" + k.kdf.cpus,
                        k.keySize, k.priority));
            for (Luks2Header.Segment g : h.segments)
                out(String.format("    segment %s: %s, offset %d, size %s, sector %d", g.id, g.encryption, g.offset,
                        g.size < 0 ? "dynamic" : String.valueOf(g.size), g.sectorSize));
            for (String w : h.warnings)
                out("    WARNING: " + w);
            return h;
        }
        catch (Exception e)
        {
            out("    LUKS2 header error: " + e.getMessage());
            return null;
        }
    }

    private static String typeName(String t)
    {
        switch (t)
        {
            case PartitionTable.TYPE_LINUX_LUKS: return " (Linux LUKS)";
            case PartitionTable.TYPE_LINUX_FS: return " (Linux filesystem)";
            case PartitionTable.TYPE_LINUX_LVM: return " (Linux LVM)";
            case "C12A7328-F81F-11D2-BA4B-00A0C93EC93B": return " (EFI system)";
            case "BC13C2FF-59E6-4262-A352-B275FD6F7172": return " (Linux /boot)";
            default: return "";
        }
    }

    private void out(String s)
    {
        Log.i(TAG, s);
        ui.post(() -> text.append(s + "\n"));
    }
}
