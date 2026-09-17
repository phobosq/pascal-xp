# pascal_probe

Minimal XP-compatible runtime capability probe.

Initial checks:
- display enumeration,
- DirectDraw initialization,
- D3D9 runtime creation.

Planned next checks:
- DirectDraw caps,
- D3D8 adapter/device creation,
- D3D9 device creation and caps,
- WGL context creation and GL vendor/renderer/version.

The source intentionally avoids modern C/C++ runtime dependencies. A dedicated VS2010/WDK7 project file will be added once the exact XP build environment is fixed.
