// Files written to removable media, one row per file write -- the falcon_usb
// collector's NG-SIEM query. Trimmed from Falcon's own "Files written to
// removable media details" dashboard: console parameters removed, Size kept
// in raw bytes, file-type label kept. The device joins look back 7 days so a
// stick plugged in before the search window still gets its make/model/serial.
// Paste it into Advanced Event Search to check it; to load a console CSV
// export instead of using the API, see `mode: csv` in config.yaml.example.
#repo=base_sensor IsOnRemovableDisk=1
| match("falcon/devicecontrol/dc_filewritten_events.csv", field=#event_simpleName, include=[writtenFileType], ignoreCase=true)
| join({#repo=base_sensor #event_simpleName=RemovableMediaVolumeMounted},
       field=VolumeSessionUUID, include=[DiskParentDeviceInstanceId], start=7d, limit=200000, mode=left)
| case {
    DiskParentDeviceInstanceId = /usb/i | ConnectionType := "USB";
    event_platform = Win | ConnectionType := "Storage spaces";
    * | ConnectionType := "PCIe";
  }
| join({#repo=base_sensor
        | in(#event_simpleName, values=[DcUsbDeviceConnected, DcUsbDeviceBlocked, DcUsbDevicePolicyViolation])
        | DiskParentDeviceInstanceId := rename(DeviceInstanceId)
        | groupBy([DiskParentDeviceInstanceId, aid, DeviceManufacturer, DeviceProduct], function=[], limit=max)},
       field=[DiskParentDeviceInstanceId, aid], include=[DeviceManufacturer, DeviceProduct], start=7d, mode=left)
| DeviceSerialNumber := splitString(DiskParentDeviceInstanceId, by="\\\\", index=2)
| table([@timestamp, aid, ComputerName, UserName, FileName, FilePath, Size, writtenFileType, ConnectionType,
         DeviceManufacturer, DeviceProduct, DeviceSerialNumber, event_platform], sortby=@timestamp, order=desc, limit=max)
