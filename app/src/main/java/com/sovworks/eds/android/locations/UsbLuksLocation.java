package com.sovworks.eds.android.locations;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.hardware.usb.UsbDevice;
import android.hardware.usb.UsbManager;
import android.net.Uri;
import android.os.Handler;
import android.os.Looper;
import android.widget.Toast;

import androidx.core.content.ContextCompat;

import com.sovworks.eds.android.Logger;
import com.sovworks.eds.android.errors.UserException;
import com.sovworks.eds.android.helpers.ProgressReporter;
import com.sovworks.eds.exceptions.WrongPasswordException;
import com.sovworks.eds.fs.FileSystem;
import com.sovworks.eds.fs.ext4.Ext4FS;
import com.sovworks.eds.locations.Location;
import com.sovworks.eds.locations.LocationsManager;
import com.sovworks.eds.locations.LocationsManagerBase;
import com.sovworks.eds.luks2.Luks2Header;
import com.sovworks.eds.luks2.Luks2Volume;
import com.sovworks.eds.luks2.Luks2WrongPassphraseException;
import com.sovworks.eds.luks2.Lvm2;
import com.sovworks.eds.luks2.SourceIO;
import com.sovworks.eds.settings.Settings;
import com.sovworks.eds.usb.AndroidBulkPipe;
import com.sovworks.eds.usb.PartitionTable;
import com.sovworks.eds.usb.UsbMassStorage;

import java.io.IOException;
import java.util.Arrays;

/**
 * A LUKS2 volume on a USB drive, opened directly over USB (no root, no kernel mount).
 * Stack: USB mass storage -> partition -> LUKS2 -> [LVM2 linear LV] -> ext2/3/4.
 *
 * Always read-only. Identified by the LUKS2 UUID, so it is found again whichever USB port or
 * device name the drive gets. Closed automatically (forced) when the drive is unplugged.
 *
 * URI: usbluks:/[path]?uuid=LUKS-UUID&location=usbdrive-uri
 */
public class UsbLuksLocation extends EDSLocationBase
{
    public static final String URI_SCHEME = "usbluks";
    private static final String PARAM_UUID = "uuid";

    public static String getLocationId(Uri uri)
    {
        return URI_SCHEME + ":" + uri.getQueryParameter(PARAM_UUID);
    }

    public UsbLuksLocation(Uri uri, LocationsManagerBase lm, Context context, Settings settings) throws Exception
    {
        this(getContainerLocationFromUri(uri, lm), uri.getQueryParameter(PARAM_UUID), context, settings);
        loadFromUri(uri);
    }

    public UsbLuksLocation(Location drive, String luksUuid, Context context, Settings settings)
    {
        super(settings, new SharedData(URI_SCHEME + ":" + luksUuid, createInternalSettings(), drive, context));
        getSharedData().uuid = luksUuid;
        getExternalSettings().setVisibleToUser(true);
    }

    private UsbLuksLocation(UsbLuksLocation sibling)
    {
        super(sibling);
    }

    public String getLuksUuid() { return getSharedData().uuid; }

    @Override
    public UsbLuksLocation copy() { return new UsbLuksLocation(this); }

    @Override
    public void loadFromUri(Uri uri)
    {
        super.loadFromUri(uri);
        String p = uri.getPath();
        if (p != null && p.startsWith("/"))
            p = p.substring(1);
        _currentPathString = p == null || p.isEmpty() ? null : p;
    }

    @Override
    public Uri getLocationUri()
    {
        return makeUri(URI_SCHEME).appendQueryParameter(PARAM_UUID, getLuksUuid()).build();
    }

    @Override
    public String getTitle()
    {
        String t = getExternalSettings().getTitle();
        if (t != null && !t.isEmpty())
            return t;
        String label = getSharedData().label;
        return label != null && !label.isEmpty() ? label : getLocation().getTitle();
    }

    @Override
    public boolean isReadOnly() { return true; }

    @Override
    public boolean isOpen() { return getSharedData().ext4 != null; }

    @Override
    public synchronized void open() throws Exception
    {
        if (isOpen())
            return;
        SharedData sd = getSharedData();
        Context ctx = getContext();
        UsbManager um = (UsbManager) ctx.getSystemService(Context.USB_SERVICE);
        UsbDriveLocation drive = (UsbDriveLocation) getLocation();

        report("Connecting to the USB drive…");
        Found f;
        try
        {
            f = find(um, drive.getSerial(), getLuksUuid());
        }
        catch (IOException e)
        {
            throw userError(e.getMessage(), e);
        }
        UsbMassStorage dev = f.dev;
        Luks2Volume vol = null;
        try
        {
            byte[] pw = getFinalPassword();
            try
            {
                vol = Luks2Volume.unlock(f.part, f.header, pw,
                        (id, kdf) -> report("Checking the password (" + kdf + ", keyslot " + id + ")…"));
            }
            catch (Luks2WrongPassphraseException e)
            {
                throw new WrongPasswordException();
            }
            finally
            {
                Arrays.fill(pw, (byte) 0);
            }
            report("Opening the file system…");
            Ext4FS fs;
            try
            {
                fs = new Ext4FS(new SourceIO(pickFileSystem(vol)));
            }
            catch (IOException e)
            {
                throw userError("Can't open the file system: " + e.getMessage(), e);
            }

            sd.dev = dev;
            sd.vol = vol;
            sd.ext4 = fs;
            sd.deviceName = f.deviceName;
            sd.label = f.header.label;
            registerDetachReceiver(ctx, sd);
            dev = null;
            vol = null; // now owned by the shared data
        }
        finally
        {
            if (vol != null)
                vol.close();
            if (dev != null)
                dev.close();
        }
    }

    @Override
    public synchronized void close(boolean force) throws IOException
    {
        super.close(force); // closes the FS wrapper -> Ext4FS (unmount; open files closed first)
        SharedData sd = getSharedData();
        if (sd.ext4 != null)
        {
            try
            {
                sd.ext4.close(true);
            }
            catch (IOException e)
            {
                Logger.log(e);
            }
            sd.ext4 = null;
        }
        if (sd.vol != null)
        {
            sd.vol.close(); // wipes the key
            sd.vol = null;
        }
        if (sd.dev != null)
        {
            sd.dev.close();
            sd.dev = null;
        }
        if (sd.detachReceiver != null)
        {
            try
            {
                getContext().getApplicationContext().unregisterReceiver(sd.detachReceiver);
            }
            catch (IllegalArgumentException ignored)
            {
            }
            sd.detachReceiver = null;
        }
    }

    @Override
    protected FileSystem createBaseFS(boolean readOnly) throws IOException
    {
        Ext4FS fs = getSharedData().ext4;
        if (fs == null)
            throw new IOException("The USB volume is closed");
        return fs;
    }

    // ------------------------------------------------------------------ device discovery

    private static final class Found
    {
        UsbMassStorage dev;
        PartitionTable.Partition part;
        Luks2Header header;
        String deviceName;
    }

    /** Finds the attached drive holding the LUKS2 volume with this UUID. Caller owns f.dev. */
    private static Found find(UsbManager um, String serial, String uuid) throws IOException
    {
        boolean noPermission = false;
        IOException lastError = null;
        for (AndroidBulkPipe.Candidate c : AndroidBulkPipe.find(um))
        {
            if (!um.hasPermission(c.device))
            {
                noPermission = true;
                continue;
            }
            String s = c.device.getSerialNumber();
            if (!serial.isEmpty() && s != null && !serial.equals(s))
                continue;
            UsbMassStorage dev = null;
            try
            {
                dev = UsbMassStorage.open(AndroidBulkPipe.open(um, c), Logger::debug);
                PartitionTable pt = PartitionTable.read(dev, dev.blockSize());
                for (PartitionTable.Partition p : pt.partitions)
                {
                    if (!Luks2Header.hasLuks2Magic(p))
                        continue;
                    Luks2Header h = Luks2Header.read(p);
                    if (uuid.equalsIgnoreCase(h.uuid))
                    {
                        Found f = new Found();
                        f.dev = dev;
                        f.part = p;
                        f.header = h;
                        f.deviceName = c.device.getDeviceName();
                        dev = null;
                        return f;
                    }
                }
            }
            catch (IOException e)
            {
                lastError = e;
            }
            finally
            {
                if (dev != null)
                    dev.close();
            }
        }
        if (lastError != null)
            throw new IOException("Can't read the USB drive: " + lastError.getMessage(), lastError);
        if (noPermission)
            throw new IOException("EDS is not allowed to access the USB drive. Open it from the menu again and allow access.");
        throw new IOException("The USB drive with this encrypted volume is not connected.");
    }

    /** The LUKS2 payload itself, or the first ext2/3/4 logical volume inside LVM. */
    private static Luks2Header.Source pickFileSystem(Luks2Volume vol) throws IOException
    {
        if (Lvm2.hasLabel(vol))
        {
            Lvm2 lvm = Lvm2.read(vol);
            for (Lvm2.LogicalVolume lv : lvm.volumes.values())
                if (Ext4FS.isExt4Image(new SourceIO(lv)))
                    return lv;
            throw new IOException("No ext2/3/4 logical volume in LVM group '" + lvm.vgName + "'"
                    + (lvm.unsupported.isEmpty() ? "" : " (unsupported: " + lvm.unsupported.keySet() + ")"));
        }
        if (Ext4FS.isExt4Image(new SourceIO(vol)))
            return vol;
        throw new IOException("The encrypted volume doesn't contain an ext2/3/4 file system");
    }

    // ------------------------------------------------------------------ unplug

    private void registerDetachReceiver(Context ctx, SharedData sd)
    {
        Context app = ctx.getApplicationContext();
        final String deviceName = sd.deviceName;
        sd.detachReceiver = new BroadcastReceiver()
        {
            @Override
            public void onReceive(Context c, Intent intent)
            {
                UsbDevice d = intent.getParcelableExtra(UsbManager.EXTRA_DEVICE, UsbDevice.class);
                if (d == null || !deviceName.equals(d.getDeviceName()))
                    return;
                final String title = getTitle();
                new Thread(() -> {
                    try
                    {
                        LocationsManager.getLocationsManager(app).closeLocation(UsbLuksLocation.this, true);
                    }
                    catch (Exception e)
                    {
                        Logger.log(e);
                    }
                    new Handler(Looper.getMainLooper()).post(() -> Toast.makeText(app,
                            "USB drive removed: " + title + " was closed", Toast.LENGTH_LONG).show());
                }, "usb-detach-close").start();
            }
        };
        // ACTION_USB_DEVICE_DETACHED is a protected system broadcast: delivered to non-exported receivers.
        ContextCompat.registerReceiver(app, sd.detachReceiver,
                new IntentFilter(UsbManager.ACTION_USB_DEVICE_DETACHED), ContextCompat.RECEIVER_NOT_EXPORTED);
    }

    /** An error EDS shows to the user verbatim (other exceptions get a generic "see the log" text). */
    private static UserException userError(String msg, Throwable cause)
    {
        UserException e = new UserException(msg, 0);
        e.initCause(cause);
        return e;
    }

    private void report(String text)
    {
        ProgressReporter r = _openingProgressReporter;
        if (r != null)
        {
            r.setText(text);
            r.setProgress(-1); // no percentage available (Argon2 runs as one native call)
        }
    }

    // ------------------------------------------------------------------ state

    protected static class SharedData extends EDSLocationBase.SharedData
    {
        SharedData(String id, InternalSettings settings, Location location, Context ctx)
        {
            super(id, settings, location, ctx);
        }

        String uuid, label, deviceName;
        UsbMassStorage dev;
        Luks2Volume vol;
        Ext4FS ext4;
        BroadcastReceiver detachReceiver;
    }

    @Override
    protected SharedData getSharedData()
    {
        return (SharedData) super.getSharedData();
    }
}
