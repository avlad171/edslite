package com.sovworks.eds.android.locations;

import android.net.Uri;

import com.sovworks.eds.fs.FileSystem;
import com.sovworks.eds.locations.LocationBase;
import com.sovworks.eds.settings.Settings;

import java.io.IOException;

/**
 * A partition of a USB mass-storage drive, as the "container" underneath a {@link UsbLuksLocation}.
 *
 * Deliberately not Openable and has no file system: the raw partition is only ever read through
 * the LUKS2 layer. It exists so code that expects every encrypted location to sit on top of another
 * location (titles, info screens, URIs) keeps working.
 *
 * URI: usbdrive://?vid=0781&pid=55ab&serial=...&part=3&product=...
 */
public class UsbDriveLocation extends LocationBase
{
    public static final String URI_SCHEME = "usbdrive";

    public static String getLocationId(Uri uri)
    {
        return URI_SCHEME + ":" + nz(uri.getQueryParameter("vid")) + ":" + nz(uri.getQueryParameter("pid"))
                + ":" + nz(uri.getQueryParameter("serial")) + ":" + nz(uri.getQueryParameter("part"));
    }

    public static Uri makeUri(int vid, int pid, String serial, int partition, String product)
    {
        return new Uri.Builder().scheme(URI_SCHEME).path("/")
                .appendQueryParameter("vid", String.format("%04x", vid))
                .appendQueryParameter("pid", String.format("%04x", pid))
                .appendQueryParameter("serial", nz(serial))
                .appendQueryParameter("part", String.valueOf(partition))
                .appendQueryParameter("product", nz(product))
                .build();
    }

    public UsbDriveLocation(Uri uri, Settings settings)
    {
        super(settings, new DriveData(getLocationId(uri)));
        _uri = uri;
    }

    private UsbDriveLocation(UsbDriveLocation sibling)
    {
        super(sibling);
        _uri = sibling._uri;
    }

    public String getSerial() { return nz(_uri.getQueryParameter("serial")); }

    public int getPartition()
    {
        try
        {
            return Integer.parseInt(nz(_uri.getQueryParameter("part")));
        }
        catch (NumberFormatException e)
        {
            return -1;
        }
    }

    public String getProduct() { return nz(_uri.getQueryParameter("product")).trim(); }

    @Override
    public String getTitle()
    {
        String p = getProduct();
        return (p.isEmpty() ? "USB drive" : p) + (getPartition() > 0 ? ", partition " + getPartition() : "");
    }

    @Override
    public String toString() { return getTitle(); }

    @Override
    public FileSystem getFS() throws IOException
    {
        throw new IOException("The raw USB partition can only be opened through its encryption layer");
    }

    @Override
    public boolean isReadOnly() { return true; }

    @Override
    public Uri getLocationUri() { return _uri; }

    @Override
    public UsbDriveLocation copy() { return new UsbDriveLocation(this); }

    private final Uri _uri;

    private static final class DriveData extends SharedData
    {
        DriveData(String id) { super(id); }
    }

    private static String nz(String s) { return s == null ? "" : s; }
}
