package com.sovworks.eds.android.navigdrawer;

import com.sovworks.eds.android.R;
import android.content.Context;
import android.hardware.usb.UsbManager;

import com.sovworks.eds.android.locations.EncFsLocationBase;
import com.sovworks.eds.android.locations.UsbDriveLocation;
import com.sovworks.eds.android.locations.UsbLuksLocation;
import com.sovworks.eds.usb.AndroidBulkPipe;
import com.sovworks.eds.locations.LocationsManager;
import com.sovworks.eds.locations.ContainerLocation;
import com.sovworks.eds.locations.EDSLocation;

import java.util.ArrayList;
import java.util.Collection;

public class DrawerContainersMenu extends DrawerSubMenuBase
{
    @Override
    public String getTitle()
    {
        return getContext().getString(R.string.containers);
    }

    public DrawerContainersMenu(DrawerControllerBase drawerController)
    {
        super(drawerController);
    }

    @Override
    protected Collection<DrawerMenuItemBase> getSubItems()
    {
        LocationsManager lm = LocationsManager.getLocationsManager(getContext());
        ArrayList<DrawerMenuItemBase> res = new ArrayList<>();
        for(EDSLocation loc: lm.getLoadedEDSLocations(true))
        {
            if(loc instanceof ContainerLocation)
                res.add(new DrawerContainerMenuItem(loc, getDrawerController()));
            else if(loc instanceof EncFsLocationBase)
                res.add(new DrawerEncFsMenuItem(loc, getDrawerController()));
        }
        addUsbItems(lm, res);
        res.add(new DrawerManageContainersMenuItem(getDrawerController()));

        return res;
    }

    /**
     * USB drives: a known LUKS volume is listed while it is open or its drive is attached (and
     * accessible); any other attached mass-storage drive gets a "USB drive" entry.
     */
    private void addUsbItems(LocationsManager lm, ArrayList<DrawerMenuItemBase> res)
    {
        UsbManager um = (UsbManager) getContext().getSystemService(Context.USB_SERVICE);
        if (um == null)
            return;
        ArrayList<AndroidBulkPipe.Candidate> unclaimed = new ArrayList<>(AndroidBulkPipe.find(um));
        for (EDSLocation loc : lm.getLoadedEDSLocations(true))
        {
            if (!(loc instanceof UsbLuksLocation))
                continue;
            UsbLuksLocation ul = (UsbLuksLocation) loc;
            String serial = ((UsbDriveLocation) ul.getLocation()).getSerial();
            AndroidBulkPipe.Candidate match = null;
            for (AndroidBulkPipe.Candidate c : unclaimed)
                if (um.hasPermission(c.device) && serial.equals(serialOf(c)))
                    match = c;
            if (match != null)
                unclaimed.remove(match);
            if (match != null || ul.isOpen())
                res.add(res.size(), new DrawerUsbLuksMenuItem(ul, getDrawerController()));
        }
        for (AndroidBulkPipe.Candidate c : unclaimed)
            res.add(new DrawerUsbDriveMenuItem(c, getDrawerController()));
    }

    private static String serialOf(AndroidBulkPipe.Candidate c)
    {
        try
        {
            String s = c.device.getSerialNumber();
            return s == null ? "" : s;
        }
        catch (SecurityException e)
        {
            return "";
        }
    }
}
