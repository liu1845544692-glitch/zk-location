# Password server-salt device test

Date: 2026-06-30

## Environment

- Device: HUAWEI EBG-AN00
- Android: 12 / API 31
- ABI: arm64-v8a
- ADB serial: 2NSDU20602005699
- Test user: `salt-device-20260630-1`
- Server: `127.0.0.1:3003` through `adb reverse`
- Password registration database: isolated temporary JSON database

## Registration

- HTTP: 201
- Native Arkworks verify: true
- Kotlin verify: true
- Server snarkjs verify: true
- Public signal count: 1
- Public signal equals commitment: true
- Commitment tamper request: HTTP 400 / `COMMITMENT_MISMATCH`
- Proof generation: 6146 ms
- Local verify: 205 ms
- Server verify: 238.984066 ms
- Total: 7208 ms
- Server database schema: 2
- Salt persisted as decimal string: true (38 digits)
- Password/witness/proof/DFA persisted: false
- Password database mode: 0600

## Login

Same-device login:

- Correct password: HTTP 200
- Wrong password: HTTP 401 / `INVALID_CREDENTIALS`
- Unknown user: HTTP 401 / `INVALID_CREDENTIALS`
- Login proof generated: false

Cross-device simulation:

- Deleted only `password_registration_salt_v1_7e964fc0096276728e73ae04.json` for the test user.
- Confirmed the local salt file remained absent.
- Server salt retrieval: success.
- Correct password: HTTP 200.
- Wrong password: HTTP 401 / `INVALID_CREDENTIALS`.
- Login proof generated: false.

Server restart:

- Registration count after restart: 1.
- Login parameters returned a decimal string salt and circuit version only.
- Response contained no commitment or proof.
- With local salt still absent, correct password login remained HTTP 200.

## Runtime

- Registration-run observed process exit: user-requested force-stop only.
- Registration process peak from exit info: PSS 288 MB, RSS 369 MB.
- Final login process: PSS 95 MB, RSS 231 MB.
- OOM: none observed.
- ANR: none observed.
- App crash: none observed.
- Native crash: none observed.
- Rust panic: none observed.
- Plaintext test password in server log or logcat: not found.
- Salt in interaction log: not found.

## Artifacts

- `device-registration-20260630.txt`
- `device-login-same-device-20260630.txt`
- `device-login-no-local-salt-20260630.txt`
- `device-login-after-server-restart-20260630.txt`
- `device-server-interactions-20260630.jsonl`
- `device-logcat-login-no-local-20260630.txt`
- `device-logcat-login-restart-20260630.txt`

The full logcat buffer was audited for all four runs before minimization. It contained no crash, ANR, OOM, native signal, Rust panic, plaintext test password, or salt match. Only the non-empty app-PID-filtered login logs were retained to avoid storing unrelated device logs.

Conclusion: PASS. Password login no longer depends on the registration device's local salt record.
