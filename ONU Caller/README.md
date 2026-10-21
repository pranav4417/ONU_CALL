# ONU CALL: install

Your Xcode project picks up files automatically, so just copy these four files into
`/Users/pranav/Music/xcode/ONU Caller/ONU Caller/` and replace the old ones:

- ContentView.swift
- JioPhone.swift
- AudioIO.swift
- Registration.swift   (new)

Then, one time only:

1. Build the audio codec:  `./setup_amr.sh "/Users/pranav/Music/xcode/ONU Caller"`
   (must end with "Done. Created:")
2. Project settings: `python3 patch_project.py ".../ONU Caller.xcodeproj/project.pbxproj"`
   (already done if you ran it before; it says "Already patched").
3. Xcode: Shift+Cmd+K, then Run on your iPhone, on your JioFiber Wi-Fi.

First launch: allow Microphone and Local Network, tap **Send OTP**, type the code
from the SMS, tap **Verify**. After that the app opens straight to the dial pad.
