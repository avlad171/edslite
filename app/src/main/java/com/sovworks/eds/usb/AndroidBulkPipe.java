package com.sovworks.eds.usb;

import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.hardware.usb.UsbConstants;
import android.hardware.usb.UsbDevice;
import android.hardware.usb.UsbDeviceConnection;
import android.hardware.usb.UsbEndpoint;
import android.hardware.usb.UsbInterface;
import android.hardware.usb.UsbManager;

import androidx.core.content.ContextCompat;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * {@link BulkPipe} over Android's USB host API, plus discovery and the permission flow.
 *
 * Opening claims the mass-storage interface with force=true, which detaches the kernel's
 * usb-storage/uas driver from it, and selects the Bulk-Only alternate setting (the kernel may
 * have left the interface in the UAS setting).
 */
public final class AndroidBulkPipe implements BulkPipe
{
    public static final int CLASS_MASS_STORAGE = 8, SUBCLASS_SCSI = 6, PROTOCOL_BOT = 0x50;

    /** A mass-storage BOT interface (one alternate setting) on an attached device. */
    public static final class Candidate
    {
        public final UsbDevice device;
        public final UsbInterface iface;
        public final UsbEndpoint in, out;

        Candidate(UsbDevice d, UsbInterface i, UsbEndpoint in, UsbEndpoint out)
        {
            device = d; iface = i; this.in = in; this.out = out;
        }

        public String describe()
        {
            return String.format("%04x:%04x %s %s (interface %d alt %d, EP in 0x%02x out 0x%02x)",
                    device.getVendorId(), device.getProductId(), nz(device.getManufacturerName()),
                    nz(device.getProductName()), iface.getId(), iface.getAlternateSetting(),
                    in.getAddress(), out.getAddress());
        }
    }

    public interface PermissionCallback
    {
        void onResult(boolean granted);
    }

    public static List<Candidate> find(UsbManager um)
    {
        List<Candidate> res = new ArrayList<>();
        for (UsbDevice d : um.getDeviceList().values())
        {
            Candidate c = botInterface(d);
            if (c != null)
                res.add(c);
        }
        return res;
    }

    static Candidate botInterface(UsbDevice d)
    {
        for (int k = 0; k < d.getInterfaceCount(); k++)
        {
            UsbInterface i = d.getInterface(k);
            if (i.getInterfaceClass() != CLASS_MASS_STORAGE || i.getInterfaceSubclass() != SUBCLASS_SCSI
                    || i.getInterfaceProtocol() != PROTOCOL_BOT)
                continue;
            UsbEndpoint in = null, out = null;
            for (int e = 0; e < i.getEndpointCount(); e++)
            {
                UsbEndpoint ep = i.getEndpoint(e);
                if (ep.getType() != UsbConstants.USB_ENDPOINT_XFER_BULK)
                    continue;
                if (ep.getDirection() == UsbConstants.USB_DIR_IN)
                {
                    if (in == null) in = ep;
                }
                else if (out == null)
                    out = ep;
            }
            if (in != null && out != null)
                return new Candidate(d, i, in, out);
        }
        return null;
    }

    /**
     * Asks the user for access to the device (system dialog) unless already granted.
     * The callback runs on the main thread.
     */
    public static void requestPermission(Context ctx, UsbDevice device, PermissionCallback cb)
    {
        UsbManager um = (UsbManager) ctx.getSystemService(Context.USB_SERVICE);
        if (um.hasPermission(device))
        {
            cb.onResult(true);
            return;
        }
        Context app = ctx.getApplicationContext();
        String action = app.getPackageName() + ".USB_PERMISSION";
        BroadcastReceiver r = new BroadcastReceiver()
        {
            @Override
            public void onReceive(Context c, Intent intent)
            {
                app.unregisterReceiver(this);
                cb.onResult(intent.getBooleanExtra(UsbManager.EXTRA_PERMISSION_GRANTED, false)
                        && um.hasPermission(device));
            }
        };
        ContextCompat.registerReceiver(app, r, new IntentFilter(action), ContextCompat.RECEIVER_NOT_EXPORTED);
        // Must be mutable: UsbManager adds the device and the result as extras.
        // Explicit package so the mutable intent can't be redirected (required on Android 14+).
        Intent i = new Intent(action).setPackage(app.getPackageName());
        PendingIntent pi = PendingIntent.getBroadcast(app, 0, i,
                PendingIntent.FLAG_MUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
        um.requestPermission(device, pi);
    }

    public static AndroidBulkPipe open(UsbManager um, Candidate c) throws IOException
    {
        if (!um.hasPermission(c.device))
            throw new IOException("no permission for the USB device");
        UsbDeviceConnection conn = um.openDevice(c.device);
        if (conn == null)
            throw new IOException("can't open the USB device");
        if (!conn.claimInterface(c.iface, true))
        {
            conn.close();
            throw new IOException("can't claim the USB mass-storage interface");
        }
        // Select the BOT alternate setting explicitly (SET_INTERFACE). The kernel may have
        // been using UAS on another alternate setting of the same interface.
        if (!conn.setInterface(c.iface))
        {
            conn.releaseInterface(c.iface);
            conn.close();
            throw new IOException("can't select the Bulk-Only alternate setting");
        }
        return new AndroidBulkPipe(um, c, conn);
    }

    private final UsbManager um;
    private final Candidate c;
    private final UsbDeviceConnection conn;
    private boolean closed;

    private AndroidBulkPipe(UsbManager um, Candidate c, UsbDeviceConnection conn)
    {
        this.um = um; this.c = c; this.conn = conn;
    }

    public Candidate candidate() { return c; }

    @Override
    public int maxPacketSize() { return c.in.getMaxPacketSize(); }

    @Override
    public int bulkOut(byte[] buf, int off, int len, int timeoutMs)
    {
        return conn.bulkTransfer(c.out, buf, off, len, timeoutMs);
    }

    @Override
    public int bulkIn(byte[] buf, int off, int len, int timeoutMs)
    {
        return conn.bulkTransfer(c.in, buf, off, len, timeoutMs);
    }

    @Override
    public boolean clearHalt(boolean in)
    {
        UsbEndpoint ep = in ? c.in : c.out;
        // CLEAR_FEATURE(ENDPOINT_HALT): bmRequestType 0x02 (host->device, standard, endpoint)
        return conn.controlTransfer(0x02, 0x01, 0, ep.getAddress(), null, 0, 2000) >= 0;
    }

    @Override
    public boolean massStorageReset()
    {
        // bmRequestType 0x21 (host->device, class, interface), bRequest 0xFF
        return conn.controlTransfer(0x21, 0xFF, 0, c.iface.getId(), null, 0, 2000) >= 0;
    }

    @Override
    public boolean isConnected()
    {
        return um.getDeviceList().containsKey(c.device.getDeviceName());
    }

    @Override
    public synchronized void close()
    {
        if (closed)
            return;
        closed = true;
        conn.releaseInterface(c.iface);
        conn.close();
    }

    private static String nz(String s) { return s == null ? "" : s.trim(); }
}
