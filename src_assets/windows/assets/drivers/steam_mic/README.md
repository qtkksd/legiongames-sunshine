# Steam Streaming Microphone driver

This directory contains the Windows driver package for the **Steam Streaming
Microphone** virtual audio device, plus an idempotent installer script.

## Why it is bundled here

Client-to-host microphone passthrough writes decoded PCM into the *render*
endpoint of the "Steam Streaming Microphone" virtual device; host applications
(Discord, OBS, browsers, games) then capture it from the device's *capture*
endpoint.

That device is normally installed by Steam (usually on the first Steam Remote
Play / Steam Link session), but its presence is not guaranteed — Steam's
`drivers` directory is often empty until a stream has run. This feature is
therefore **self-contained**: we ship the driver here and always install from
this bundled package, never from a local Steam installation.

## Layout

```
steam_mic/
  install_steam_microphone.ps1   idempotent installer (checks first, skips if present)
  x64/
    SteamStreamingMicrophone.inf
    SteamStreamingMicrophone.sys
    steamstreamingmicrophone.cat
    WdfCoinstaller01009.dll
```

These files are installed to `<assets>/drivers/steam_mic/` and, on startup,
Sunshine best-effort installs the device if it is not already present (see
`install_steam_microphone_driver()` in `src/platform/windows/audio.cpp`). The
install is skipped whenever the device already exists in the PnP device store,
including when it is disabled or unplugged.

## Manual install

Run from an elevated prompt:

```powershell
powershell -ExecutionPolicy Bypass -File install_steam_microphone.ps1
```

Use `-Force` to reinstall even if the device is already present.

## Provenance / licence

The driver binaries are **Valve Corporation**'s (part of the Steam Link audio
drivers), redistributed here solely so Sunshine can provision the virtual device
on hosts where Steam has not installed it. They are unmodified. Valve does not
publish an official standalone download. Remove this directory and use the local
Steam driver package instead if redistribution is undesirable.
