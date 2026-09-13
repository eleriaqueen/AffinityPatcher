# Affinity analytics patch

> Stops Affinity's non-opt-out analytics upload at load time, without modifying
> or renaming any file that ships with Affinity.

Affinity sends Snowplow analytics to Canva even when analytics consent is
refused. Patching the managed consent properties does not stop it, because the
decision is made in native code in `libacs.dll`. This kit neutralises the
native send path in memory, so nothing on disk changes and the Authenticode
signature on `libacs.dll` stays valid.

## Install

Copy `mscms.dll`, `dll_universal_patcher.dll` and `patches.json` into the
directory containing `Affinity.exe`. Nothing else changes, and no Affinity file
is renamed or edited.

To uninstall, delete those three files.

Clear `sp.db` and its `-wal` sidecar once on first install, under
`%APPDATA%\Affinity\Common\3.0\`. Events queued before the patch was deployed
would otherwise flush on the next launch.

## How it works

The patcher writes a single `0xC3` (`ret`) over the entry of
`Affinity::CloudServices::Analytics::Emitter::DispatchSnowplowSelfDescribingEvent`
in `libacs.dll`, in memory, as the module loads.

That function is the only egress point. It has exactly two code callers,
`Emitter::RecordEvent` and `Emitter::RecordActivityDetectedEvent`, and
`Emitter::StartSession` does not reach it. It returns `void`, and MSVC x64 has
the caller destroy by-value parameters, so returning immediately is safe for the
ABI and leaks nothing.

The consent check is dead on one of those paths.
`RecordActivityDetectedEvent` calls `HasConsent()` and discards the result: the
next instruction overwrites `rax` and the flag is never tested. `RecordEvent`
also skips the consent gate entirely for event types 4 and 5 (`canva_session`
and `affinity_id`). Only offline mode blocks those paths.

## Proxy generation

To regenerate the proxy, with `<APP_DIR>` as the directory holding
`Affinity.exe`:

```
dll-proxy-generator.exe ^
    --import-dll "dll_universal_patcher.dll" --import "dummy" ^
    -o "<APP_DIR>\mscms.dll" ^
    "C:\Windows\System32\mscms.dll"
```

`-p` is omitted on purpose. It defaults to the same file in `System32`, which is
the forwarding target wanted here.

## Limitations

The Snowplow tracker and local session bookkeeping are still created, and
`sess.db` still gets a session row. Nothing is transmitted, because nothing is
ever dispatched, but that local state exists.

A persistent `urn:affinitycloud:anon-device:<id>` identifier survives deletion of
both `sp.db` and `sess.db`. It is held elsewhere, most likely `cs.dat`, which is
unconfirmed. Delete that too for a clean identity.

The candidate list from Procmon is per machine. `mscms.dll` is a Windows
component present on all supported systems, but re-run the trace if a build ever
stops probing it.

The native crash reporting stack is not covered: `Backtrace.dll`,
`libcrashpad.dll` and `crashpad_handler.exe`, which runs as its own process. The
managed `GetCrashReportUploadPolicy` patch may not gate it, for the same reason
the managed consent patch does not gate `libacs.dll`. This has not been analysed.

## License

The files written for this kit (`patches.json`, `verify_patch.py` and this
document) are part of AffinityPatcher and carry its MIT licence.

`dll_universal_patcher.dll` and `dll-proxy-generator.exe` are by namazso, under
the BSD Zero Clause License (0BSD).

`mscms.dll` here is output from that generator. It holds export forwarder stubs
naming the Windows `mscms.dll` entry points and contains no Microsoft code.
