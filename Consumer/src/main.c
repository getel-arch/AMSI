#include <windows.h>
#include <stdio.h>
#include <amsi.h>       // from Windows SDK
#include <strsafe.h>

int main(void)
{
    HAMSICONTEXT ctx = NULL;
    HAMSISESSION session = 0;
    HRESULT hr;
    AMSI_RESULT result;

    // App name (ANSI)
    const char *appName = "MyApp";
    WCHAR appNameW[64];
    MultiByteToWideChar(CP_ACP, 0, appName, -1, appNameW, ARRAYSIZE(appNameW));

    // Initialize AMSI
    hr = AmsiInitialize(appNameW, &ctx);
    if (FAILED(hr)) {
        printf("AmsiInitialize failed: 0x%08lx\n", hr);
        return 1;
    }

    // Open a session (optional)
    hr = AmsiOpenSession(ctx, &session);
    if (FAILED(hr)) {
        printf("AmsiOpenSession failed: 0x%08lx\n", hr);
        AmsiUninitialize(ctx);
        return 1;
    }

    // String to scan (ANSI)
    const char *text = "Write-Host 'Invoke-Mimikatz'";
    WCHAR textW[256];
    MultiByteToWideChar(CP_ACP, 0, text, -1, textW, ARRAYSIZE(textW));

    WCHAR contentNameW[] = L"TestInput";

    hr = AmsiScanString(ctx, textW, contentNameW, session, &result);
    if (SUCCEEDED(hr)) {
        if (AmsiResultIsMalware(result))
            printf("AmsiScanString: MALWARE detected (result=%u)\n", result);
        else
            printf("AmsiScanString: CLEAN (result=%u)\n", result);
    } else {
        printf("AmsiScanString failed: 0x%08lx\n", hr);
    }

    // Binary buffer scan example
    unsigned char buf[] = { 0xDE, 0xAD, 0xBE, 0xEF };
    hr = AmsiScanBuffer(ctx, buf, (ULONG)sizeof(buf), contentNameW, session, &result);
    if (SUCCEEDED(hr)) {
        if (AmsiResultIsMalware(result))
            printf("AmsiScanBuffer: MALWARE detected (result=%u)\n", result);
        else
            printf("AmsiScanBuffer: CLEAN (result=%u)\n", result);
    } else {
        printf("AmsiScanBuffer failed: 0x%08lx\n", hr);
    }

    // Cleanup
    AmsiCloseSession(ctx, session);
    AmsiUninitialize(ctx);
    return 0;
}