package com.sovworks.eds.android.receivers;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.hardware.usb.UsbManager;
import android.os.Handler;
import android.os.Looper;

import com.sovworks.eds.android.Logger;
import com.sovworks.eds.android.locations.ExternalStorageLocation;
import com.sovworks.eds.locations.LocationsManager;
import com.sovworks.eds.locations.LocationsManagerBase;

public class MediaMountedReceiver extends BroadcastReceiver
{
	public MediaMountedReceiver(LocationsManagerBase lm)
	{
		_lm = lm;
	}

	@Override
	public void onReceive(Context context, Intent intent) 
	{
		Logger.debug("MediaMountedReceiver");
		if(_lm == null)
			return;
		String action = intent.getAction();
		if(UsbManager.ACTION_USB_DEVICE_ATTACHED.equals(action) || UsbManager.ACTION_USB_DEVICE_DETACHED.equals(action))
			handle(context, intent); // raw USB device: nothing to wait for
		else
			// Give the system time to finish mounting/unmounting the storage volume. This used to be a
			// Thread.sleep(3000) right here, which froze the UI for 3 s on every plug/unplug.
			_handler.postDelayed(() -> handle(context, intent), 3000);
	}

	private void handle(Context context, Intent intent)
	{
		LocationsManagerBase lm = _lm;
		String mountPath = intent.getDataString();
        ExternalStorageLocation loc = mountPath != null ? new ExternalStorageLocation(context, "ext storage", mountPath, null) : null;
		switch (intent.getAction())
		{
			case UsbManager.ACTION_USB_DEVICE_ATTACHED:
				Logger.debug("ACTION_USB_DEVICE_ATTACHED");
				lm.updateDeviceLocations();
				LocationsManager.broadcastLocationAdded(context, loc);
				break;
			case Intent.ACTION_MEDIA_MOUNTED:
				Logger.debug("ACTION_MEDIA_MOUNTED");
				lm.updateDeviceLocations();
				LocationsManager.broadcastLocationAdded(context, loc);
				break;
			case Intent.ACTION_MEDIA_UNMOUNTED:
				Logger.debug("ACTION_MEDIA_UNMOUNTED");
				lm.updateDeviceLocations();
				LocationsManager.broadcastLocationRemoved(context, loc);
				break;
			case Intent.ACTION_MEDIA_REMOVED:
				Logger.debug("ACTION_MEDIA_REMOVED");
				lm.updateDeviceLocations();
				LocationsManager.broadcastLocationRemoved(context, loc);
				break;
			case UsbManager.ACTION_USB_DEVICE_DETACHED:
				Logger.debug("ACTION_USB_DEVICE_DETACHED");
				lm.updateDeviceLocations();
				LocationsManager.broadcastLocationRemoved(context, loc);
				break;
		}
	}

	private final Handler _handler = new Handler(Looper.getMainLooper());
	private final LocationsManagerBase _lm;
}
