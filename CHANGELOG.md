# Changes

## 1.2.0

- **Deleted BAM entries are read back.** Run as administrator, History Parser reads the registry file on disk and
  lists BAM entries that were deleted, flagged unless Windows' own clean-up explains them (the program was not run
  for 7 days, or its file was gone before the last boot).
- **Files picked in Open and Save dialogs.** The last 20 exe, dll, jar, script and archive files picked per file
  type, and which programs showed a dialog. The library chosen in an injector's file box stays listed after the file
  is gone. Only the newest pick of each list is dated.
- **Who deleted the change journal.** When a USN journal was deleted or recreated, the process that asked for it and
  the time are shown, if Windows logged the request. It is one finding with the deletion, not a second one.
- **Programs on a volume with no drive letter.** Such a volume is hidden from Explorer. Programs that ran from one
  now get a path that can be opened, are hashed and are flagged. A record about a volume that is not connected now
  says so instead of showing a device name.
- **Virtual disks.** A .vhd or .vhdx file attached as a disk and removed again is listed with the USB history.
- **The setup-environment switch.** The registry key `Control\MiniNT`, which stops Windows writing events without
  stopping the event log service, is checked and flagged.
