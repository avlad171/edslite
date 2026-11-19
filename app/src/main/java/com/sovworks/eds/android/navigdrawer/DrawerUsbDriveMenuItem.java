package com.sovworks.eds.android.navigdrawer;

import android.content.Context;
import android.graphics.drawable.Drawable;
import android.hardware.usb.UsbManager;
import android.net.Uri;
import android.os.Handler;
import android.os.Looper;
import android.util.TypedValue;
import android.view.View;
import android.widget.Toast;

import com.sovworks.eds.android.Logger;
import com.sovworks.eds.android.R;
import com.sovworks.eds.android.filemanager.activities.FileManagerActivity;
import com.sovworks.eds.android.locations.UsbDriveLocation;
import com.sovworks.eds.android.locations.UsbLuksLocation;
import com.sovworks.eds.android.settings.UserSettings;
import com.sovworks.eds.locations.Location;
import com.sovworks.eds.locations.LocationsManager;
import com.sovworks.eds.luks2.Luks2Header;
import com.sovworks.eds.usb.AndroidBulkPipe;
import com.sovworks.eds.usb.PartitionTable;
import com.sovworks.eds.usb.UsbMassStorage;

/**
 * Drawer entry for an attached USB mass-storage drive that hasn't been looked into yet.
 * Tap: ask for USB access, find the LUKS2 partition, register it as a {@link UsbLuksLocation}
 * and open it (password dialog, then the file manager). Reads only.
 */
public class DrawerUsbDriveMenuItem extends DrawerMenuItemBase
{
    public DrawerUsbDriveMenuItem(AndroidBulkPipe.Candidate drive, DrawerControllerBase drawerController)
    {
        super(drawerController);
        _drive = drive;
    }

    @Override
    public String getTitle()
    {
        String p = _drive.device.getProductName();
        return "USB drive" + (p == null || p.trim().isEmpty() ? "" : ": " + p.trim());
    }

    @Override
    public Drawable getIcon()
    {
        TypedValue tv = new TypedValue();
        Context ctx = getContext();
        ctx.getTheme().resolveAttribute(R.attr.lockIcon, tv, true);
        //noinspection deprecation
        return ctx.getResources().getDrawable(tv.resourceId);
    }

    @Override
    public void onClick(View view, int position)
    {
        super.onClick(view, position);
        final FileManagerActivity act = getDrawerController().getMainActivity();
        final DrawerControllerBase dc = getDrawerController();
        AndroidBulkPipe.requestPermission(act, _drive.device, granted -> {
            if (!granted)
            {
                Toast.makeText(act, "EDS needs access to the USB drive to open it", Toast.LENGTH_LONG).show();
                return;
            }
            Toast.makeText(act, "Looking for an encrypted volume…", Toast.LENGTH_SHORT).show();
            new Thread(() -> probeAndOpen(act, dc), "usb-probe").start();
        });
    }

    private void probeAndOpen(FileManagerActivity act, DrawerControllerBase dc)
    {
        Handler ui = new Handler(Looper.getMainLooper());
        UsbManager um = (UsbManager) act.getSystemService(Context.USB_SERVICE);
        int luksCount = 0;
        int partNo = -1;
        String uuid = null;
        try (UsbMassStorage dev = UsbMassStorage.open(AndroidBulkPipe.open(um, _drive), Logger::debug))
        {
            PartitionTable pt = PartitionTable.read(dev, dev.blockSize());
            for (PartitionTable.Partition p : pt.partitions)
                if (Luks2Header.hasLuks2Magic(p))
                {
                    Luks2Header h = Luks2Header.read(p);
                    if (luksCount++ == 0)
                    {
                        partNo = p.number;
                        uuid = h.uuid;
                    }
                }
        }
        catch (Exception e)
        {
            Logger.log(e);
            ui.post(() -> Logger.showAndLog(act, e));
            return;
        }
        if (uuid == null)
        {
            ui.post(() -> Toast.makeText(act, "No LUKS2 encrypted volume found on this USB drive", Toast.LENGTH_LONG).show());
            return;
        }
        final int found = luksCount;
        final String luksUuid = uuid;
        final int partition = partNo;
        ui.post(() -> {
            try
            {
                UsbLuksLocation loc = register(act, luksUuid, partition);
                if (found > 1)
                    Toast.makeText(act, found + " encrypted volumes found; opening the one on partition " + partition,
                            Toast.LENGTH_LONG).show();
                dc.reloadItems();
                new DrawerUsbLuksMenuItem(loc, dc).openLocation();
            }
            catch (Exception e)
            {
                Logger.showAndLog(act, e);
            }
        });
    }

    private UsbLuksLocation register(Context ctx, String luksUuid, int partition) throws Exception
    {
        LocationsManager lm = LocationsManager.getLocationsManager(ctx);
        String serial;
        try
        {
            serial = _drive.device.getSerialNumber();
        }
        catch (SecurityException e)
        {
            serial = null;
        }
        Uri driveUri = UsbDriveLocation.makeUri(_drive.device.getVendorId(), _drive.device.getProductId(), serial,
                partition, _drive.device.getProductName());
        Location drive = lm.getLocation(driveUri); // creates and registers it if new
        Location existing = lm.findExistingLocation(UsbLuksLocation.URI_SCHEME + ":" + luksUuid);
        if (existing instanceof UsbLuksLocation)
            return (UsbLuksLocation) existing;
        UsbLuksLocation loc = new UsbLuksLocation(drive, luksUuid, ctx, UserSettings.getSettings(ctx));
        lm.addNewLocation(loc, false);
        return loc;
    }

    private final AndroidBulkPipe.Candidate _drive;
}
