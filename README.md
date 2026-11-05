# IL2CPP External Dump

Pure C++ (ImGui) Android overlay to dump **dump.cs** from **any IL2CPP process** on the device.

- **Domain / module resolve:** same approach as [mlbb-esp-pure](https://github.com/panelforsale080-byte/mlbb-esp-pure) (`remote_il2cpp`, ptrace `il2cpp_domain_get`, conRent-style symbol scan).
- **Dump format:** conRentV1-style `dump.cs` (classes, fields, methods, offsets).
- **UI:** pick process → **Dump dump.cs** → live log + progress bar.

## Usage

1. Install and open the app (full-screen native UI — **no overlay**).
2. Open the target game (IL2CPP loaded).
3. **Refresh** → select process → **Generate dump.cs** (watch log + progress).
4. Output: `Android/data/com.il2cpp.externaldump/files/dump.cs`.

Root helps read other apps’ memory.

## Build

```bash
./gradlew assembleDebug
```

GitHub Actions produces `il2cpp-external-dump-debug` artifact on push to `main`.
