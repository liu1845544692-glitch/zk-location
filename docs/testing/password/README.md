# Password proof test records

This directory keeps only the conclusion-level records needed to reproduce or
audit the current implementation:

- `arkworks-verify-root-cause.txt`: Arkworks verification root cause and fix.
- `witness-normalization-regression.txt`: Location and seven regex regressions.
- `android-len8-len16-len32-final.txt`: Final password proof matrix.
- `android-registration-final.txt`: Local Android registration result.
- `server-registration-final.txt`: Server registration result.
- `login-final.txt`: Same-device password login result.
- `device-server-salt-final-20260630.md`: Final physical-device server-salt and cross-device simulation result.
- `device-*-20260630.*`: Registration, login, server interaction, and logcat evidence for that run.
- `mopro-architecture.txt`: Android/mopro runtime architecture audit.

Raw logcat, screenshots, memory samples, generated witnesses, and duplicate
device runs were intentionally removed. Fixed password inputs remain under
`zk-location/test-vectors/password/`.
