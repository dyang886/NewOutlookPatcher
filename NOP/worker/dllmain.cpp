#include <wrl.h>
#include <wil/com.h>
#include <winrt/Windows.Foundation.Collections.h>
#include <winrt/Windows.Web.Syndication.h>
#include <iostream>
#include <Windows.h>
#include <commctrl.h>
#include "WebView2.h"
#include "WebView2EnvironmentOptions.h"

#pragma region "IAT patching routine"
// https://blog.neteril.org/blog/2016/12/23/diverting-functions-windows-iat-patching/
inline bool VnPatchIAT(HMODULE hMod, const char* libName, const char* funcName, uintptr_t hookAddr) {
    // Increment module reference count to prevent other threads from unloading it while we're working with it
    HMODULE module;
    if (!::GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCWSTR)hMod, &module)) return false;

    // Get a reference to the import table to locate the kernel32 entry
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)module;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((uintptr_t)module + dos->e_lfanew);
    if (!nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress) { ::FreeLibrary(module); return false; }
    PIMAGE_IMPORT_DESCRIPTOR importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((uintptr_t)module +
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    // In the import table find the entry that corresponds to kernel32
    bool found = false;
    while (importDescriptor->Characteristics && importDescriptor->Name) {
        PSTR importName = (PSTR)((PBYTE)module + importDescriptor->Name);
        if (::_stricmp(importName, libName) == 0) { found = true; break; }
        importDescriptor++;
    }
    if (!found) { ::FreeLibrary(module); return false; }

    // From the kernel32 import descriptor, go over its IAT thunks to
    // find the one used by the rest of the code to call GetProcAddress
    PIMAGE_THUNK_DATA oldthunk = (PIMAGE_THUNK_DATA)((PBYTE)module + importDescriptor->OriginalFirstThunk);
    PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((PBYTE)module + importDescriptor->FirstThunk);
    while (thunk->u1.Function) {
        PROC* funcStorage = (PROC*)&thunk->u1.Function;

        bool bFound = false;
        if (oldthunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
            bFound = (!(*((WORD*)&(funcName)+1)) && IMAGE_ORDINAL32(oldthunk->u1.Ordinal) == (DWORD_PTR)funcName);
        }
        else {
            PIMAGE_IMPORT_BY_NAME byName = (PIMAGE_IMPORT_BY_NAME)((uintptr_t)module + oldthunk->u1.AddressOfData);
            bFound = ((*((WORD*)&(funcName)+1)) && !::_stricmp((char*)byName->Name, funcName));
        }

        // Found it, now let's patch it
        if (bFound) {
            // Get the memory page where the info is stored
            MEMORY_BASIC_INFORMATION mbi;
            ::VirtualQuery(funcStorage, &mbi, sizeof(MEMORY_BASIC_INFORMATION));

            // Try to change the page to be writable if it's not already
            if (!::VirtualProtect(mbi.BaseAddress, mbi.RegionSize, PAGE_READWRITE, &mbi.Protect)) {
                ::FreeLibrary(module);
                return false;
            }

            // Store our hook
            *funcStorage = (PROC)hookAddr;

            // Restore the old flag on the page
            DWORD dwOldProtect;
            ::VirtualProtect(mbi.BaseAddress, mbi.RegionSize, mbi.Protect, &dwOldProtect);

            // Profit
            ::FreeLibrary(module);
            return true;
        }

        thunk++;
        oldthunk++;
    }

    ::FreeLibrary(module);
    return false;
}

inline BOOL VnPatchDelayIAT(HMODULE hMod, const char* libName, const char* funcName, uintptr_t hookAddr) {
    // Increment module reference count to prevent other threads from unloading it while we're working with it
    HMODULE lib;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCWSTR)hMod, &lib)) return FALSE;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)lib;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((uintptr_t)lib + dos->e_lfanew);
    if (!nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress) { FreeLibrary(lib); return FALSE; }
    PIMAGE_DELAYLOAD_DESCRIPTOR dload = (PIMAGE_DELAYLOAD_DESCRIPTOR)((uintptr_t)lib +
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress);
    while (dload->DllNameRVA)
    {
        char* dll = (char*)((uintptr_t)lib + dload->DllNameRVA);
        if (!_stricmp(dll, libName)) {
#ifdef _LIBVALINET_DEBUG_HOOKING_IATPATCH
            printf("[PatchDelayIAT] Found %s in IAT.\n", libName);
#endif

            PIMAGE_THUNK_DATA firstthunk = (PIMAGE_THUNK_DATA)((uintptr_t)lib + dload->ImportNameTableRVA);
            PIMAGE_THUNK_DATA functhunk = (PIMAGE_THUNK_DATA)((uintptr_t)lib + dload->ImportAddressTableRVA);
            while (firstthunk->u1.AddressOfData)
            {
                if (firstthunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
                {
                    if (!(*((WORD*)&(funcName)+1)) && IMAGE_ORDINAL32(firstthunk->u1.Ordinal) == (DWORD_PTR)funcName)
                    {
                        DWORD oldProtect;
                        if (VirtualProtect(&functhunk->u1.Function, sizeof(uintptr_t), PAGE_EXECUTE_READWRITE, &oldProtect))
                        {
                            functhunk->u1.Function = (uintptr_t)hookAddr;
                            VirtualProtect(&functhunk->u1.Function, sizeof(uintptr_t), oldProtect, &oldProtect);
#ifdef _LIBVALINET_DEBUG_HOOKING_IATPATCH
                            printf("[PatchDelayIAT] Patched 0x%x in %s to 0x%p.\n", funcName, libName, hookAddr);
#endif
                            FreeLibrary(lib);
                            return TRUE;
                        }
                        FreeLibrary(lib);
                        return FALSE;
                    }
                }
                else
                {
                    PIMAGE_IMPORT_BY_NAME byName = (PIMAGE_IMPORT_BY_NAME)((uintptr_t)lib + firstthunk->u1.AddressOfData);
                    if ((*((WORD*)&(funcName)+1)) && !_stricmp((char*)byName->Name, funcName))
                    {
                        DWORD oldProtect;
                        if (VirtualProtect(&functhunk->u1.Function, sizeof(uintptr_t), PAGE_EXECUTE_READWRITE, &oldProtect))
                        {
                            functhunk->u1.Function = (uintptr_t)hookAddr;
                            VirtualProtect(&functhunk->u1.Function, sizeof(uintptr_t), oldProtect, &oldProtect);
#ifdef _LIBVALINET_DEBUG_HOOKING_IATPATCH
                            printf("[PatchDelayIAT] Patched %s in %s to 0x%p.\n", funcName, libName, hookAddr);
#endif
                            FreeLibrary(lib);
                            return TRUE;
                        }
                        FreeLibrary(lib);
                        return FALSE;
                    }
                }
                functhunk++;
                firstthunk++;
            }
        }
        dload++;
    }
    FreeLibrary(lib);
    return FALSE;
}
#pragma endregion

#pragma region "Hooks"
/*
LRESULT(*__WndProc)(HWND, UINT, WPARAM, LPARAM) = nullptr;
LRESULT _WndProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    return __WndProc(hWnd, uMsg, wParam, lParam);
}
*/

// The selector and component lists are patched in the binary by the GUI (unchecked items are overwritten with spaces), so each item must stay a contiguous string.
// The script is idempotent: it runs once when the document is created (before any page script, so nothing is ever painted unstyled),
// and again on NavigationCompleted as a fallback in case the early injection did not happen.
//
// Outlook's class names (.jYY8g, .syTot, ...) are generated and change from one Outlook build to the next, while its React component
// names (MessageAdList, LeftnavUpsell, ...) are set explicitly in its code and survive updates. So elements are primarily hidden by the
// component that renders them (any component whose name starts with an entry of hiddenComponents): a MutationObserver marks such elements
// with data-nop-hidden as soon as they are inserted, which happens before the next paint. Stable ids and the current class names are kept
// in the CSS as a second, independent way to match.
static const wchar_t* const g_script = L"\
(() => {\n\
if (window[Symbol.for('NewOutlookPatcher')]) return;\n\
window[Symbol.for('NewOutlookPatcher')] = true;\n\
const styleId = 'NewOutlookPatcher';\n\
const cssClass = \"\
#OwaContainer, #OwaContainerSlot1, "                                 /* First "email" ad when online */ L"\
.kk1xx._Bfyd.iIsOF.IjQyD, .kk1xx.lHRXq.iIsOF.IjQyD, "                /* First "email" ad when offline */ L"\
.jYY8g, "                                                            /* Space reserved for the first "email" ad while it loads */ L"\
.syTot, "                                                            /* Lower left OneDrive subscription banner */ L"\
.GssDD, "                                                            /* Display ads panel on the right (or bottom) side */ L"\
[id='34318026-c018-414b-abb3-3e32dfb9cc4c'], "                       /* Word button in sidebar */ L"\
[id='c5251a9b-a95d-4595-91ee-a39e6eed3db2'], "                       /* Excel button in sidebar */ L"\
[id='48cb9ead-1c19-4e1f-8ed9-3d60a7e52b18'], "                       /* PowerPoint button in sidebar */ L"\
[id='59391057-d7d7-49fd-a041-d8e4080f05ec'], "                       /* To Do button in sidebar */ L"\
[id='0d5c91ee-5be2-4b79-81ed-23e6c4580427'], "                       /* To Do button in sidebar (newer app, ToDoMetaOs) */ L"\
[id='39109bd4-9389-4731-b8d6-7cc1a128d0b3'], "                       /* OneDrive button in sidebar */ L"\
[data-tid='appbar-flyout-button'], "                                 /* More apps button in sidebar */ L"\
[data-nop-hidden], "                                                 /* Elements rendered by hiddenComponents */ L"\
[id='D64D0004-2A11-442B-9586-F49009D4852B'] { display: none !important; }\";\n\
const hiddenComponents = \"\
MessageAdList "                                                      /* First "email" ad, its loading shimmer and the space reserved for it */ L"\
LeftnavUpsell "                                                      /* Lower left OneDrive subscription banner */ L"\
AdsPanel "                                                           /* Display ads panel on the right (or bottom) side, and its placeholder (AdsPanelStub) */ L"\
\".split(' ').filter(Boolean);\n\
const inject = () => {\n\
    if (document.getElementById(styleId)) return true;\n\
    const parent = document.head || document.documentElement;\n\
    if (!parent) return false;\n\
    const styleElement = document.createElement('style');\n\
    styleElement.id = styleId;\n\
    styleElement.appendChild(document.createTextNode(cssClass));\n\
    parent.appendChild(styleElement);\n\
    return true;\n\
};\n\
if (!inject()) new MutationObserver((_, observer) => { if (inject()) observer.disconnect(); }).observe(document, { childList: true });\n\
if (!hiddenComponents.length || window !== window.top) return;\n\
let fiberKey = null;\n\
const getFiber = element => {\n\
    if (fiberKey && element[fiberKey]) return element[fiberKey];\n\
    const key = Object.keys(element).find(key => key.startsWith('__reactFiber$'));\n\
    if (key) fiberKey = key;\n\
    return key && element[key];\n\
};\n\
const componentName = type => type && (type.displayName || type.name || (type.render && (type.render.displayName || type.render.name)) || (type.type && (type.type.displayName || type.type.name)));\n\
const isRenderedByHiddenComponent = element => {\n\
    const fiber = getFiber(element);\n\
    for (let owner = fiber && fiber.return; owner && typeof owner.type !== 'string'; owner = owner.return) {\n\
        const name = componentName(owner.type);\n\
        if (typeof name === 'string' && hiddenComponents.some(prefix => name.startsWith(prefix))) return true;\n\
    }\n\
    return false;\n\
};\n\
const hide = element => { if (isRenderedByHiddenComponent(element)) element.setAttribute('data-nop-hidden', ''); };\n\
const hideAll = root => { hide(root); for (const element of root.getElementsByTagName('*')) hide(element); };\n\
if (document.documentElement) hideAll(document.documentElement);\n\
new MutationObserver(records => { for (const record of records) for (const node of record.addedNodes) if (node.nodeType === 1) hideAll(node); }).observe(document, { childList: true, subtree: true });\n\
})();\n\
";
// .root-192, .splitButtonMenuButton-220 { background-color: transparent !important; color: var(--neutralDark) !important; } " /* Deemphasize New mail button */ L"\

// Styles the page and enables F12 in a controller Outlook has just created, before Outlook itself gets to use it
void PatchController(ICoreWebView2Controller* createdController) {
    if (createdController != nullptr) {
        winrt::com_ptr<ICoreWebView2> webview;
        winrt::check_hresult(createdController->get_CoreWebView2(webview.put()));

        // Registered before Outlook gets the controller (and thus before its first navigation), so the styles exist before the first paint
        webview->AddScriptToExecuteOnDocumentCreated(g_script, Microsoft::WRL::Callback<ICoreWebView2AddScriptToExecuteOnDocumentCreatedCompletedHandler>([](HRESULT errorCode, LPCWSTR id) -> HRESULT {
            return S_OK;
            }).Get());

        EventRegistrationToken tkn_NavigationCompleted;
        winrt::check_hresult(webview->add_NavigationCompleted(Microsoft::WRL::Callback<ICoreWebView2NavigationCompletedEventHandler>([](ICoreWebView2* sender, ICoreWebView2NavigationCompletedEventArgs* args) -> HRESULT {

            //::MessageBoxW(nullptr, g_script, L"", 0);
            sender->ExecuteScript(g_script, Microsoft::WRL::Callback<ICoreWebView2ExecuteScriptCompletedHandler>([&](HRESULT errorCode, LPCWSTR resultObjectAsJson) -> HRESULT {
                return S_OK;
                }).Get());

            return S_OK;
            }).Get(), &tkn_NavigationCompleted));

        volatile int dummyF12Enabled = 0;
        const wchar_t* isF12Enabled = L"y_1A36CD25-E20F-4D0D-B1E6-3CC4307E1488";
        if (isF12Enabled[0 + dummyF12Enabled] == L'y') {
            EventRegistrationToken tkn_AcceleratorKeyPressed;
            winrt::check_hresult(createdController->add_AcceleratorKeyPressed(Microsoft::WRL::Callback<ICoreWebView2AcceleratorKeyPressedEventHandler>([](ICoreWebView2Controller* sender, ICoreWebView2AcceleratorKeyPressedEventArgs* args) -> HRESULT {

                COREWEBVIEW2_KEY_EVENT_KIND kind;
                winrt::check_hresult(args->get_KeyEventKind(&kind));
                if (kind == COREWEBVIEW2_KEY_EVENT_KIND_KEY_UP) {
                    UINT key;
                    winrt::check_hresult(args->get_VirtualKey(&key));
                    if (key == VK_F12) {
                        winrt::check_hresult(args->put_Handled(true));
                        winrt::com_ptr<ICoreWebView2> webview;
                        winrt::check_hresult(sender->get_CoreWebView2(webview.put()));
                        webview->OpenDevToolsWindow();
                    }
                }

                return S_OK;
                }).Get(), &tkn_AcceleratorKeyPressed));
        }

        /*
        HWND parentWindow = nullptr;
        createdController->get_ParentWindow(&parentWindow);
        ::SetLastError(0);
        __WndProc = reinterpret_cast<LRESULT(*)(HWND, UINT, WPARAM, LPARAM)>(::GetWindowLongPtrW(parentWindow, GWLP_WNDPROC));
        if (::GetLastError() == ERROR_SUCCESS && __WndProc) {
            ::SetWindowLongPtrW(parentWindow, GWLP_WNDPROC, reinterpret_cast<LONG_PTR>(_WndProc));
        }
        */
    }
}

// Outlook's completion handlers are wrapped rather than patched in their vtables: Outlook uses several handler classes (one per call site),
// each with its own vtable, and a single saved original Invoke would end up calling the wrong one
Microsoft::WRL::ComPtr<ICoreWebView2CreateCoreWebView2ControllerCompletedHandler> WrapControllerCompletedHandler(ICoreWebView2CreateCoreWebView2ControllerCompletedHandler* controllerCompletedHandler) {
    Microsoft::WRL::ComPtr<ICoreWebView2CreateCoreWebView2ControllerCompletedHandler> originalHandler(controllerCompletedHandler);
    return Microsoft::WRL::Callback<ICoreWebView2CreateCoreWebView2ControllerCompletedHandler>([originalHandler](HRESULT errorCode, ICoreWebView2Controller* createdController) -> HRESULT {
        try {
            PatchController(createdController);
        }
        catch (...) {}
        return originalHandler->Invoke(errorCode, createdController);
        });
}

template <typename T>
void PatchVtblEntry(void* object, size_t index, T hook, T& original) {
    void** vtbl = *(void***)object;
    if (vtbl[index] == reinterpret_cast<void*>(hook)) return;
    // Only one original can be saved per entry, so leave alone any other implementation of the same method
    if (original != nullptr && vtbl[index] != reinterpret_cast<void*>(original)) return;
    DWORD oldProtect = 0;
    if (::VirtualProtect(&vtbl[index], sizeof(uintptr_t), PAGE_EXECUTE_READWRITE, &oldProtect)) {
        original = reinterpret_cast<T>(vtbl[index]);
        vtbl[index] = reinterpret_cast<void*>(hook);
        ::VirtualProtect(&vtbl[index], sizeof(uintptr_t), oldProtect, &oldProtect);
    }
}

HRESULT(*__ICoreWebView2Environment_CreateCoreWebView2Controller)(ICoreWebView2Environment*, HWND, ICoreWebView2CreateCoreWebView2ControllerCompletedHandler*) = nullptr;
HRESULT STDMETHODCALLTYPE _ICoreWebView2Environment_CreateCoreWebView2Controller(ICoreWebView2Environment* _this, HWND parentWindow, ICoreWebView2CreateCoreWebView2ControllerCompletedHandler* controllerCompletedHandler) {
    auto wrappedHandler = controllerCompletedHandler ? WrapControllerCompletedHandler(controllerCompletedHandler) : nullptr;
    return __ICoreWebView2Environment_CreateCoreWebView2Controller(_this, parentWindow, wrappedHandler ? wrappedHandler.Get() : controllerCompletedHandler);
}

HRESULT(*__ICoreWebView2Environment10_CreateCoreWebView2ControllerWithOptions)(ICoreWebView2Environment10*, HWND, ICoreWebView2ControllerOptions*, ICoreWebView2CreateCoreWebView2ControllerCompletedHandler*) = nullptr;
HRESULT STDMETHODCALLTYPE _ICoreWebView2Environment10_CreateCoreWebView2ControllerWithOptions(ICoreWebView2Environment10* _this, HWND parentWindow, ICoreWebView2ControllerOptions* options, ICoreWebView2CreateCoreWebView2ControllerCompletedHandler* controllerCompletedHandler) {
    auto wrappedHandler = controllerCompletedHandler ? WrapControllerCompletedHandler(controllerCompletedHandler) : nullptr;
    return __ICoreWebView2Environment10_CreateCoreWebView2ControllerWithOptions(_this, parentWindow, options, wrappedHandler ? wrappedHandler.Get() : controllerCompletedHandler);
}

void PatchEnvironment(ICoreWebView2Environment* createdEnvironment) {
    PatchVtblEntry(createdEnvironment, 3, _ICoreWebView2Environment_CreateCoreWebView2Controller, __ICoreWebView2Environment_CreateCoreWebView2Controller); // ICoreWebView2Environment::CreateCoreWebView2Controller
    // Newer Outlook (1.2026+) creates its controllers with options (to use profiles)
    winrt::com_ptr<ICoreWebView2Environment10> environment10;
    if (SUCCEEDED(createdEnvironment->QueryInterface(IID_PPV_ARGS(environment10.put())))) {
        PatchVtblEntry(environment10.get(), 21, _ICoreWebView2Environment10_CreateCoreWebView2ControllerWithOptions, __ICoreWebView2Environment10_CreateCoreWebView2ControllerWithOptions); // ICoreWebView2Environment10::CreateCoreWebView2ControllerWithOptions
    }
}

HRESULT(*__CreateCoreWebView2EnvironmentWithOptions)(PCWSTR, PCWSTR, ICoreWebView2EnvironmentOptions*, ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler*) = nullptr;
STDAPI _CreateCoreWebView2EnvironmentWithOptions(PCWSTR browserExecutableFolder, PCWSTR userDataFolder, ICoreWebView2EnvironmentOptions* environmentOptions, ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler* environmentCreatedHandler) {
    if (!__CreateCoreWebView2EnvironmentWithOptions) {
        // When hooked through the delay-load IAT, WebView2Loader.dll may not have been loaded yet
        auto hMod = ::GetModuleHandleW(L"WebView2Loader.dll");
        if (!hMod) hMod = ::LoadLibraryW(L"WebView2Loader.dll");
        if (!hMod) return HRESULT_FROM_WIN32(::GetLastError());
        __CreateCoreWebView2EnvironmentWithOptions = reinterpret_cast<HRESULT(*)(PCWSTR, PCWSTR, ICoreWebView2EnvironmentOptions*, ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler*)>(::GetProcAddress(hMod, "CreateCoreWebView2EnvironmentWithOptions"));
        if (!__CreateCoreWebView2EnvironmentWithOptions) return HRESULT_FROM_WIN32(::GetLastError());
    }

#ifdef NOP_REMOTE_DEBUGGING
    // Diagnostic builds only (never in releases): exposes Outlook's WebView2 to the DevTools protocol when Outlook is
    // started with NEWOUTLOOKPATCHER_REMOTE_DEBUGGING_PORT set, e.g. to find what to hide after an Outlook update
    wchar_t debuggingPort[8]{};
    if (environmentOptions && ::GetEnvironmentVariableW(L"NEWOUTLOOKPATCHER_REMOTE_DEBUGGING_PORT", debuggingPort, ARRAYSIZE(debuggingPort))) {
        wil::unique_cotaskmem_string arguments;
        environmentOptions->get_AdditionalBrowserArguments(&arguments);
        std::wstring newArguments = arguments ? arguments.get() : L"";
        newArguments += L" --remote-debugging-port=";
        newArguments += debuggingPort;
        environmentOptions->put_AdditionalBrowserArguments(newArguments.c_str());
    }
#endif

    if (environmentCreatedHandler) {
        Microsoft::WRL::ComPtr<ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler> originalHandler(environmentCreatedHandler);
        auto wrappedHandler = Microsoft::WRL::Callback<ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler>([originalHandler](HRESULT errorCode, ICoreWebView2Environment* createdEnvironment) -> HRESULT {
            if (createdEnvironment != nullptr) {
                PatchEnvironment(createdEnvironment);
            }
            return originalHandler->Invoke(errorCode, createdEnvironment);
            });
        if (wrappedHandler) {
            return __CreateCoreWebView2EnvironmentWithOptions(browserExecutableFolder, userDataFolder, environmentOptions, wrappedHandler.Get());
        }
    }
    return __CreateCoreWebView2EnvironmentWithOptions(browserExecutableFolder, userDataFolder, environmentOptions, environmentCreatedHandler);
}
#pragma endregion

#pragma region "DLL load notifications"
// Outlook no longer calls WebView2Loader.dll from olk.exe itself, but from modules loaded later on (nh.dll, delay-loaded by olknh.dll),
// so every module gets hooked as it loads. The loader sends these notifications after it has resolved the module's imports.
#define LDR_DLL_NOTIFICATION_REASON_LOADED 1

typedef struct _LDR_DLL_LOADED_NOTIFICATION_DATA {
    ULONG Flags;
    PVOID FullDllName;
    PVOID BaseDllName;
    PVOID DllBase;
    ULONG SizeOfImage;
} LDR_DLL_LOADED_NOTIFICATION_DATA, * PLDR_DLL_LOADED_NOTIFICATION_DATA;

typedef VOID(CALLBACK* PLDR_DLL_NOTIFICATION_FUNCTION)(ULONG NotificationReason, PLDR_DLL_LOADED_NOTIFICATION_DATA NotificationData, PVOID Context);
typedef LONG(NTAPI* LdrRegisterDllNotification_t)(ULONG Flags, PLDR_DLL_NOTIFICATION_FUNCTION NotificationFunction, PVOID Context, PVOID* Cookie);

void HookWebView2Loader(HMODULE hMod) {
    ::VnPatchIAT(hMod, "WebView2Loader.dll", "CreateCoreWebView2EnvironmentWithOptions", reinterpret_cast<uintptr_t>(_CreateCoreWebView2EnvironmentWithOptions));
    ::VnPatchDelayIAT(hMod, "WebView2Loader.dll", "CreateCoreWebView2EnvironmentWithOptions", reinterpret_cast<uintptr_t>(_CreateCoreWebView2EnvironmentWithOptions));
}

VOID CALLBACK OnDllNotification(ULONG NotificationReason, PLDR_DLL_LOADED_NOTIFICATION_DATA NotificationData, PVOID Context) {
    if (NotificationReason == LDR_DLL_NOTIFICATION_REASON_LOADED) {
        HookWebView2Loader(reinterpret_cast<HMODULE>(NotificationData->DllBase));
    }
}

PVOID g_dllNotificationCookie = nullptr;
#pragma endregion

#pragma region "AppVerifier infrastructure"
#define DLL_PROCESS_VERIFIER 4

typedef struct _RTL_VERIFIER_THUNK_DESCRIPTOR {
    PCHAR ThunkName;
    PVOID ThunkOldAddress;
    PVOID ThunkNewAddress;
} RTL_VERIFIER_THUNK_DESCRIPTOR, * PRTL_VERIFIER_THUNK_DESCRIPTOR;

typedef struct _RTL_VERIFIER_DLL_DESCRIPTOR {
    PWCHAR DllName;
    ULONG DllFlags;
    PVOID DllAddress;
    PRTL_VERIFIER_THUNK_DESCRIPTOR DllThunks;
} RTL_VERIFIER_DLL_DESCRIPTOR, * PRTL_VERIFIER_DLL_DESCRIPTOR;

typedef void (NTAPI* RTL_VERIFIER_DLL_LOAD_CALLBACK) (
    PWSTR DllName,
    PVOID DllBase,
    SIZE_T DllSize,
    PVOID Reserved);
typedef void (NTAPI* RTL_VERIFIER_DLL_UNLOAD_CALLBACK) (
    PWSTR DllName,
    PVOID DllBase,
    SIZE_T DllSize,
    PVOID Reserved);
typedef void (NTAPI* RTL_VERIFIER_NTDLLHEAPFREE_CALLBACK) (
    PVOID AllocationBase,
    SIZE_T AllocationSize);

typedef struct _RTL_VERIFIER_PROVIDER_DESCRIPTOR {
    ULONG Length;
    PRTL_VERIFIER_DLL_DESCRIPTOR ProviderDlls;
    RTL_VERIFIER_DLL_LOAD_CALLBACK ProviderDllLoadCallback;
    RTL_VERIFIER_DLL_UNLOAD_CALLBACK ProviderDllUnloadCallback;

    PWSTR VerifierImage;
    ULONG VerifierFlags;
    ULONG VerifierDebug;

    PVOID RtlpGetStackTraceAddress;
    PVOID RtlpDebugPageHeapCreate;
    PVOID RtlpDebugPageHeapDestroy;

    RTL_VERIFIER_NTDLLHEAPFREE_CALLBACK ProviderNtdllHeapFreeCallback;
} RTL_VERIFIER_PROVIDER_DESCRIPTOR;

RTL_VERIFIER_DLL_DESCRIPTOR noHooks{};
RTL_VERIFIER_PROVIDER_DESCRIPTOR desc = {
    sizeof(desc),
    &noHooks,
    [](auto, auto, auto, auto) {},
    [](auto, auto, auto, auto) {},
    nullptr, 0, 0,
    nullptr, nullptr, nullptr,
    [](auto, auto) {},
};
#pragma endregion

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    UNREFERENCED_PARAMETER(lpvReserved);

    switch (fdwReason) {
    case DLL_PROCESS_ATTACH:
        ::DisableThreadLibraryCalls(hinstDLL);
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        break;
    case DLL_PROCESS_VERIFIER:
        *(PVOID*)lpvReserved = &desc;
        HookWebView2Loader(::GetModuleHandleW(nullptr));
        if (auto LdrRegisterDllNotification = reinterpret_cast<LdrRegisterDllNotification_t>(::GetProcAddress(::GetModuleHandleW(L"ntdll.dll"), "LdrRegisterDllNotification"))) {
            LdrRegisterDllNotification(0, OnDllNotification, nullptr, &g_dllNotificationCookie);
        }
        break;
    }
    return true;
}
