package com.sovworks.eds.android.navigdrawer;

import android.content.Context;
import android.graphics.drawable.Drawable;
import android.os.Bundle;
import android.util.TypedValue;

import com.sovworks.eds.android.R;
import com.sovworks.eds.android.filemanager.activities.FileManagerActivity;
import com.sovworks.eds.android.filemanager.fragments.FileListViewFragment;
import com.sovworks.eds.android.locations.UsbLuksLocation;
import com.sovworks.eds.android.locations.closer.fragments.LocationCloserBaseFragment;
import com.sovworks.eds.android.locations.closer.fragments.OMLocationCloserFragment;
import com.sovworks.eds.android.locations.opener.fragments.EDSLocationOpenerFragment;
import com.sovworks.eds.android.locations.opener.fragments.LocationOpenerBaseFragment;
import com.sovworks.eds.locations.Location;

/** Drawer entry for a LUKS2 volume on a USB drive: password dialog, then the file manager. */
public class DrawerUsbLuksMenuItem extends DrawerLocationMenuItem
{
    public static class Opener extends EDSLocationOpenerFragment
    {
        @Override
        public void onLocationOpened(Location location)
        {
            Bundle args = getArguments();
            FileManagerActivity.openFileManager(
                    (FileManagerActivity) getActivity(),
                    location,
                    args != null ? args.getInt(FileListViewFragment.ARG_SCROLL_POSITION, 0) : 0);
        }
    }

    public DrawerUsbLuksMenuItem(UsbLuksLocation location, DrawerControllerBase drawerController)
    {
        super(location, drawerController);
    }

    @Override
    public UsbLuksLocation getLocation()
    {
        return (UsbLuksLocation) super.getLocation();
    }

    @Override
    public Drawable getIcon()
    {
        TypedValue tv = new TypedValue();
        Context ctx = getContext();
        ctx.getTheme().resolveAttribute(getLocation().isOpen() ? R.attr.lockOpenIcon : R.attr.lockIcon, tv, true);
        //noinspection deprecation
        return ctx.getResources().getDrawable(tv.resourceId);
    }

    @Override
    protected LocationOpenerBaseFragment getOpener()
    {
        return new Opener();
    }

    @Override
    protected LocationCloserBaseFragment getCloser()
    {
        return new OMLocationCloserFragment();
    }

    @Override
    protected boolean hasSettings()
    {
        return false;
    }
}
