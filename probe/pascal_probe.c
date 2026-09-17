#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <ddraw.h>
#include <d3d9.h>
#include <GL/gl.h>

static void probe_display(void) {
    DISPLAY_DEVICEA dd;
    DWORD i = 0;
    ZeroMemory(&dd, sizeof(dd));
    dd.cb = sizeof(dd);
    puts("[display]");
    while (EnumDisplayDevicesA(NULL, i++, &dd, 0)) {
        printf("name=%s string=%s flags=0x%08lx id=%s\n",
               dd.DeviceName, dd.DeviceString, dd.StateFlags, dd.DeviceID);
        ZeroMemory(&dd, sizeof(dd));
        dd.cb = sizeof(dd);
    }
}

static void probe_ddraw(void) {
    LPDIRECTDRAW dd = NULL;
    HRESULT hr = DirectDrawCreate(NULL, &dd, NULL);
    printf("[ddraw] DirectDrawCreate=0x%08lx\n", (unsigned long)hr);
    if (SUCCEEDED(hr) && dd) IDirectDraw_Release(dd);
}

static void probe_d3d9(void) {
    IDirect3D9 *d3d = Direct3DCreate9(D3D_SDK_VERSION);
    printf("[d3d9] Direct3DCreate9=%s\n", d3d ? "OK" : "FAIL");
    if (d3d) IDirect3D9_Release(d3d);
}

int main(void) {
    OSVERSIONINFOA os;
    ZeroMemory(&os, sizeof(os));
    os.dwOSVersionInfoSize = sizeof(os);
    GetVersionExA(&os);
    printf("pascal_probe 0.1\nWindows %lu.%lu build %lu %s\n",
           os.dwMajorVersion, os.dwMinorVersion, os.dwBuildNumber, os.szCSDVersion);
    probe_display();
    probe_ddraw();
    probe_d3d9();
    puts("[opengl] runtime probing will be expanded after the baseline build is verified on XP.");
    return 0;
}
