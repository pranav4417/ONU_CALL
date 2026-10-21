#!/usr/bin/env python3
"""
Adds every setting ONU CALL needs to the Xcode project, so no clicking through
Build Settings. Quit Xcode first, then run:

  python3 patch_project.py "/Users/pranav/Music/xcode/ONU Caller/ONU Caller.xcodeproj/project.pbxproj"

A backup is saved next to it as project.pbxproj.bak.
"""
import os, shutil, sys

if len(sys.argv) != 2 or not sys.argv[1].endswith("project.pbxproj"):
    sys.exit('usage: python3 patch_project.py ".../ONU Caller.xcodeproj/project.pbxproj"')

path = sys.argv[1]
text = open(path, encoding="utf-8").read()

if "SWIFT_OBJC_BRIDGING_HEADER" in text:
    sys.exit("Already patched, nothing to do.")

shutil.copy(path, path + ".bak")

NEW = [
    'SWIFT_OBJC_BRIDGING_HEADER = "$(SRCROOT)/AMR/ONU-Bridging-Header.h";',
    'HEADER_SEARCH_PATHS = "\\"$(SRCROOT)/AMR/include\\"";',
    'LIBRARY_SEARCH_PATHS = "\\"$(SRCROOT)/AMR/lib\\"";',
    "OTHER_LDFLAGS = (",
    '\t"-lopencore-amrwb",',
    '\t"-lvo-amrwbenc",',
    '\t"-lc++",',
    ");",
    'INFOPLIST_KEY_CFBundleDisplayName = "ONU CALL";',
    'INFOPLIST_KEY_NSMicrophoneUsageDescription = "ONU CALL uses the microphone for calls.";',
    'INFOPLIST_KEY_NSLocalNetworkUsageDescription = "ONU CALL connects to your router.";',
    "INFOPLIST_KEY_UIBackgroundModes = audio;",
]

out, hits = [], 0
for line in text.split("\n"):
    if "SWIFT_DEFAULT_ACTOR_ISOLATION" in line:
        line = line.replace("MainActor", "nonisolated")   # background-thread code must not be main-actor
    out.append(line)
    if line.strip().startswith("PRODUCT_BUNDLE_IDENTIFIER"):   # only the app target's configs
        indent = line[: len(line) - len(line.lstrip())]
        out.extend(indent + n for n in NEW)
        hits += 1

if hits == 0:
    sys.exit("Could not find the app target settings; nothing changed.")

open(path, "w", encoding="utf-8").write("\n".join(out))
print(f"Patched {hits} build configurations (Debug/Release). Backup: {path}.bak")

root = os.path.dirname(os.path.dirname(path))
amr = os.path.join(root, "AMR")
need = [os.path.join(amr, "ONU-Bridging-Header.h"),
        os.path.join(amr, "lib", "libopencore-amrwb.a"),
        os.path.join(amr, "lib", "libvo-amrwbenc.a")]
missing = [n for n in need if not os.path.exists(n)]
if missing:
    print("\nBUT the codec files are missing, so run setup_amr.sh first:")
    for m in missing:
        print("  missing:", m)
else:
    print("Codec files found in", amr)
print("\nNow open the project, press Shift+Cmd+K (clean), then build.")
