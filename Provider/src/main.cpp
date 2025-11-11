#include <windows.h>
#include <amsi.h>
#include <combaseapi.h>
#include <stdio.h>
#include <strsafe.h>
#include <vector>
#include <string>
#include <algorithm>

// {12345678-1234-1234-1234-123456789012} - Generate your own GUID
static const GUID CLSID_AmsiProvider = 
{ 0x12345678, 0x1234, 0x1234, { 0x12, 0x34, 0x12, 0x34, 0x56, 0x78, 0x90, 0x12 } };

// Signature database structure
struct MalwareSignature {
    std::wstring pattern;
    std::wstring name;
    AMSI_RESULT threat_level;
};

// Global signature database
static std::vector<MalwareSignature> g_signatures = {
    { L"Invoke-Expression", L"PowerShell.IEX", AMSI_RESULT_DETECTED },
    { L"IEX", L"PowerShell.IEX.Short", AMSI_RESULT_DETECTED },
    { L"DownloadString", L"PowerShell.WebDownload", AMSI_RESULT_DETECTED },
    { L"System.Net.WebClient", L"PowerShell.WebClient", AMSI_RESULT_DETECTED },
    { L"Start-Process", L"PowerShell.ProcessStart", AMSI_RESULT_DETECTED },
    { L"cmd.exe /c", L"CommandExecution", AMSI_RESULT_DETECTED },
    { L"powershell.exe -enc", L"PowerShell.Encoded", AMSI_RESULT_DETECTED },
    { L"[System.Convert]::FromBase64String", L"PowerShell.Base64Decode", AMSI_RESULT_DETECTED },
    { L"New-Object System.IO.MemoryStream", L"PowerShell.MemoryStream", AMSI_RESULT_DETECTED },
    { L"Reflection.Assembly", L"PowerShell.Reflection", AMSI_RESULT_DETECTED }
};

// Signature matching function
AMSI_RESULT ScanContentForSignatures(const void* buffer, ULONG length, std::wstring& detectedThreat)
{
    if (!buffer || length == 0)
        return AMSI_RESULT_CLEAN;

    // Convert buffer to wide string for text analysis
    std::wstring content;
    
    // Try to interpret as Unicode text first
    if (length >= 2 && length % 2 == 0)
    {
        const wchar_t* wbuffer = static_cast<const wchar_t*>(buffer);
        content = std::wstring(wbuffer, length / 2);
    }
    else
    {
        // Convert from ANSI to Unicode
        const char* cbuffer = static_cast<const char*>(buffer);
        int wideLen = MultiByteToWideChar(CP_ACP, 0, cbuffer, length, nullptr, 0);
        if (wideLen > 0)
        {
            content.resize(wideLen);
            MultiByteToWideChar(CP_ACP, 0, cbuffer, length, &content[0], wideLen);
        }
    }

    // Convert to lowercase for case-insensitive matching
    std::transform(content.begin(), content.end(), content.begin(), ::towlower);

    // Check against signatures
    for (const auto& sig : g_signatures)
    {
        std::wstring pattern = sig.pattern;
        std::transform(pattern.begin(), pattern.end(), pattern.begin(), ::towlower);
        
        if (content.find(pattern) != std::wstring::npos)
        {
            detectedThreat = sig.name;
            return sig.threat_level;
        }
    }

    return AMSI_RESULT_CLEAN;
}

// Proper AMSI Provider implementation
class AmsiProvider : public IAntimalwareProvider
{
private:
    ULONG m_refCount;
    
public:
    AmsiProvider() : m_refCount(1) {}
    
    // IUnknown methods
    STDMETHODIMP QueryInterface(REFIID riid, void** ppvObject) override
    {
        if (riid == IID_IUnknown || riid == __uuidof(IAntimalwareProvider))
        {
            *ppvObject = this;
            AddRef();
            return S_OK;
        }
        *ppvObject = nullptr;
        return E_NOINTERFACE;
    }
    
    STDMETHODIMP_(ULONG) AddRef() override
    {
        return InterlockedIncrement(&m_refCount);
    }
    
    STDMETHODIMP_(ULONG) Release() override
    {
        ULONG count = InterlockedDecrement(&m_refCount);
        if (count == 0)
            delete this;
        return count;
    }
    
    // IAntimalwareProvider methods
    STDMETHODIMP Scan(IAmsiStream* stream, AMSI_RESULT* result) override
    {
        if (!stream || !result)
            return E_INVALIDARG;

        *result = AMSI_RESULT_CLEAN;

        // Get content size
        ULONGLONG streamSize = 0;
        HRESULT hr = stream->GetAttribute(AMSI_ATTRIBUTE_CONTENT_SIZE, sizeof(streamSize), 
                                        reinterpret_cast<unsigned char*>(&streamSize), nullptr);
        if (FAILED(hr))
            return hr;

        // Limit scan size to prevent excessive memory usage
        const ULONG maxScanSize = 1024 * 1024; // 1MB
        ULONG scanSize = static_cast<ULONG>(min(streamSize, maxScanSize));

        if (scanSize == 0)
            return S_OK;

        // Allocate buffer and read content
        std::vector<unsigned char> buffer(scanSize);
        ULONG bytesRead = 0;
        hr = stream->Read(0, scanSize, buffer.data(), &bytesRead);
        if (FAILED(hr))
            return hr;

        // Scan for signatures
        std::wstring detectedThreat;
        AMSI_RESULT scanResult = ScanContentForSignatures(buffer.data(), bytesRead, detectedThreat);
        
        if (scanResult != AMSI_RESULT_CLEAN)
        {
            // Log detection (in real implementation, use proper logging)
            OutputDebugStringA("AMSI Provider: Threat detected - ");
            OutputDebugStringW(detectedThreat.c_str());
            OutputDebugStringA("\n");
        }

        *result = scanResult;
        return S_OK;
    }

    STDMETHODIMP_(void) CloseSession(ULONGLONG sessionId) override
    {
        // Clean up session-specific resources
    }

    STDMETHODIMP DisplayName(LPWSTR* displayName) override
    {
        if (!displayName)
            return E_INVALIDARG;

        const wchar_t* name = L"Custom Signature-Based AMSI Provider";
        size_t nameLen = wcslen(name) + 1;
        
        *displayName = static_cast<LPWSTR>(CoTaskMemAlloc(nameLen * sizeof(wchar_t)));
        if (!*displayName)
            return E_OUTOFMEMORY;
            
        wcscpy_s(*displayName, nameLen, name);
        return S_OK;
    }
};

// Class factory for creating AmsiProvider instances
class AmsiProviderFactory : public IClassFactory
{
private:
    ULONG m_refCount;
    
public:
    AmsiProviderFactory() : m_refCount(1) {}
    
    // IUnknown methods
    STDMETHODIMP QueryInterface(REFIID riid, void** ppvObject) override
    {
        if (riid == IID_IUnknown || riid == IID_IClassFactory)
        {
            *ppvObject = this;
            AddRef();
            return S_OK;
        }
        *ppvObject = nullptr;
        return E_NOINTERFACE;
    }
    
    STDMETHODIMP_(ULONG) AddRef() override
    {
        return InterlockedIncrement(&m_refCount);
    }
    
    STDMETHODIMP_(ULONG) Release() override
    {
        ULONG count = InterlockedDecrement(&m_refCount);
        if (count == 0)
            delete this;
        return count;
    }
    
    // IClassFactory methods
    STDMETHODIMP CreateInstance(IUnknown* pUnkOuter, REFIID riid, void** ppvObject) override
    {
        if (pUnkOuter != nullptr)
            return CLASS_E_NOAGGREGATION;
            
        AmsiProvider* provider = new AmsiProvider();
        if (!provider)
            return E_OUTOFMEMORY;
            
        HRESULT hr = provider->QueryInterface(riid, ppvObject);
        provider->Release();
        return hr;
    }
    
    STDMETHODIMP LockServer(BOOL fLock) override
    {
        return S_OK;
    }
};

// Updated AmsiStream implementation for better compatibility
class AmsiStream : public IAmsiStream
{
private:
    ULONG m_refCount;
    std::vector<unsigned char> m_data;
    
public:
    AmsiStream(const void* data, ULONG size) : m_refCount(1)
    {
        if (data && size > 0)
        {
            m_data.resize(size);
            memcpy(m_data.data(), data, size);
        }
    }
    
    // IUnknown methods
    STDMETHODIMP QueryInterface(REFIID riid, void** ppvObject) override
    {
        if (riid == IID_IUnknown || riid == __uuidof(IAmsiStream))
        {
            *ppvObject = this;
            AddRef();
            return S_OK;
        }
        *ppvObject = nullptr;
        return E_NOINTERFACE;
    }
    
    STDMETHODIMP_(ULONG) AddRef() override
    {
        return InterlockedIncrement(&m_refCount);
    }
    
    STDMETHODIMP_(ULONG) Release() override
    {
        ULONG count = InterlockedDecrement(&m_refCount);
        if (count == 0)
            delete this;
        return count;
    }
    
    // IAmsiStream methods
    STDMETHODIMP GetAttribute(AMSI_ATTRIBUTE attribute, ULONG dataSize, unsigned char* data, ULONG* retData) override
    {
        switch (attribute)
        {
        case AMSI_ATTRIBUTE_APP_NAME:
            {
                const wchar_t* appName = L"CustomAmsiProvider";
                size_t nameSize = (wcslen(appName) + 1) * sizeof(wchar_t);
                if (dataSize >= nameSize)
                {
                    wcscpy_s((wchar_t*)data, dataSize / sizeof(wchar_t), appName);
                    *retData = (ULONG)nameSize;
                    return S_OK;
                }
                *retData = (ULONG)nameSize;
                return E_NOT_SUFFICIENT_BUFFER;
            }
        case AMSI_ATTRIBUTE_CONTENT_NAME:
            {
                const wchar_t* contentName = L"ScanContent";
                size_t nameSize = (wcslen(contentName) + 1) * sizeof(wchar_t);
                if (dataSize >= nameSize)
                {
                    wcscpy_s((wchar_t*)data, dataSize / sizeof(wchar_t), contentName);
                    *retData = (ULONG)nameSize;
                    return S_OK;
                }
                *retData = (ULONG)nameSize;
                return E_NOT_SUFFICIENT_BUFFER;
            }
        case AMSI_ATTRIBUTE_CONTENT_SIZE:
            {
                if (dataSize >= sizeof(ULONGLONG))
                {
                    *reinterpret_cast<ULONGLONG*>(data) = m_data.size();
                    *retData = sizeof(ULONGLONG);
                    return S_OK;
                }
                *retData = sizeof(ULONGLONG);
                return E_NOT_SUFFICIENT_BUFFER;
            }
        default:
            return E_INVALIDARG;
        }
    }
    
    STDMETHODIMP Read(ULONGLONG position, ULONG size, unsigned char* buffer, ULONG* readSize) override
    {
        if (!buffer || !readSize)
            return E_INVALIDARG;

        *readSize = 0;

        if (position >= m_data.size())
            return S_OK; // EOF

        ULONG available = static_cast<ULONG>(m_data.size() - position);
        ULONG toRead = min(size, available);
        
        if (toRead > 0)
        {
            memcpy(buffer, m_data.data() + position, toRead);
            *readSize = toRead;
        }

        return S_OK;
    }
};

// DLL entry point
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    return TRUE;
}

// COM exports
extern "C" HRESULT __stdcall DllGetClassObject(REFCLSID rclsid, REFIID riid, void** ppv)
{
    if (rclsid == CLSID_AmsiProvider)
    {
        AmsiProviderFactory* factory = new AmsiProviderFactory();
        if (!factory)
            return E_OUTOFMEMORY;
            
        HRESULT hr = factory->QueryInterface(riid, ppv);
        factory->Release();
        return hr;
    }
    return CLASS_E_CLASSNOTAVAILABLE;
}

extern "C" HRESULT __stdcall DllCanUnloadNow(void)
{
    return S_OK;
}

extern "C" HRESULT __stdcall DllRegisterServer(void)
{
    // Registry entries for AMSI provider
    const wchar_t* clsidStr = L"{12345678-1234-1234-1234-123456789012}";
    char keyPath[256];
    HKEY hKey;
    
    // Register CLSID
    sprintf_s(keyPath, "CLSID\\{12345678-1234-1234-1234-123456789012}");
    if (RegCreateKeyExA(HKEY_CLASSES_ROOT, keyPath, 0, nullptr, 0, KEY_WRITE, nullptr, &hKey, nullptr) == ERROR_SUCCESS)
    {
        RegSetValueExA(hKey, nullptr, 0, REG_SZ, (BYTE*)"Custom AMSI Provider", sizeof("Custom AMSI Provider"));
        RegCloseKey(hKey);
    }
    
    // Register InprocServer32
    sprintf_s(keyPath, "CLSID\\{12345678-1234-1234-1234-123456789012}\\InprocServer32");
    if (RegCreateKeyExA(HKEY_CLASSES_ROOT, keyPath, 0, nullptr, 0, KEY_WRITE, nullptr, &hKey, nullptr) == ERROR_SUCCESS)
    {
        char modulePath[MAX_PATH];
        GetModuleFileNameA(GetModuleHandleA(nullptr), modulePath, MAX_PATH);
        RegSetValueExA(hKey, nullptr, 0, REG_SZ, (BYTE*)modulePath, (DWORD)(strlen(modulePath) + 1));
        RegSetValueExA(hKey, "ThreadingModel", 0, REG_SZ, (BYTE*)"Both", sizeof("Both"));
        RegCloseKey(hKey);
    }
    
    return S_OK;
}

extern "C" HRESULT __stdcall DllUnregisterServer(void)
{
    const char* keyPath = "CLSID\\{12345678-1234-1234-1234-123456789012}";
    RegDeleteTreeA(HKEY_CLASSES_ROOT, keyPath);
    
    return S_OK;
}
