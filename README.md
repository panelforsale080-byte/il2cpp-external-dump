# IL2CPP External Dump

Pure C++ (ImGui) Android overlay to dump **dump.cs** from **any IL2CPP process** on the device.

- **Domain / module resolve:** same approach as [mlbb-esp-pure](https://github.com/panelforsale080-byte/mlbb-esp-pure) (`remote_il2cpp`, ptrace `il2cpp_domain_get`, conRent-style symbol scan).
- **Dump format:** conRentV1-style `dump.cs` (classes, fields, methods, offsets).
- **UI:** pick process → **Dump dump.cs** → live log + progress bar.

## Usage

1. Install APK (root recommended to read other apps’ memory).
2. Allow overlay → **Start overlay**.
3. Open the target game (wait until IL2CPP is loaded).
4. Tap **≡** → **Refresh processes** → select PID → **Dump dump.cs**.
5. Output: `Android/data/com.il2cpp.externaldump/files/dump.cs` (or app files dir from context).

## Build

```bash
./gradlew assembleDebug
```

GitHub Actions produces `il2cpp-external-dump-debug` artifact on push to `main`.
