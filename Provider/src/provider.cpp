#include <windows.h>
#include <amsi.h>

// Registry key for AMSI providers
const wchar_t* AMSI_PROVIDER_GUID = L"{dd3970a9-1289-429a-acfb-f6fc23559596}";
const wchar_t* PROVIDER_NAME = L"Custom AMSI Provider";

STDAPI DllRegisterServer()
{
    HKEY hKey;
    LONG result;
    
    // Create registry key for the AMSI provider
    wchar_t keyPath[256];
    swprintf_s(keyPath, L"SOFTWARE\\Microsoft\\AMSI\\Providers\\%s", AMSI_PROVIDER_GUID);
    
    result = RegCreateKeyExW(
        HKEY_LOCAL_MACHINE,
        keyPath,
        0,
        NULL,
        REG_OPTION_NON_VOLATILE,
        KEY_WRITE,
        NULL,
        &hKey,
        NULL
    );
    
    if (result != ERROR_SUCCESS)
        return HRESULT_FROM_WIN32(result);
    
    // Set the provider name
    result = RegSetValueExW(
        hKey,
        NULL,
        0,
        REG_SZ,
        (BYTE*)PROVIDER_NAME,
        (wcslen(PROVIDER_NAME) + 1) * sizeof(wchar_t)
    );
    
    RegCloseKey(hKey);
    
    return (result == ERROR_SUCCESS) ? S_OK : HRESULT_FROM_WIN32(result);
}

STDAPI DllUnregisterServer()
{
    wchar_t keyPath[256];
    swprintf_s(keyPath, L"SOFTWARE\\Microsoft\\AMSI\\Providers\\%s", AMSI_PROVIDER_GUID);
    
    LONG result = RegDeleteKeyW(HKEY_LOCAL_MACHINE, keyPath);
    return (result == ERROR_SUCCESS || result == ERROR_FILE_NOT_FOUND) ? S_OK : HRESULT_FROM_WIN32(result);
}

STDAPI DllCanUnloadNow()
{
    return S_OK;
}

STDAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, LPVOID* ppv)
{
    return CLASS_E_CLASSNOTAVAILABLE;
}
