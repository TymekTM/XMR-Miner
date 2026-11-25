#include "tray.h"
#include "log.h"
#include "miner/miner.h"
#include "miner/watchdog.h"

#ifdef _WIN32
#include <windows.h>
#include <shellapi.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define AUTOSTART_REG_PATH L"Software\\Microsoft\\Windows\\CurrentVersion\\Run"
#define AUTOSTART_REG_NAME L"XMR-Miner"

#define WM_TRAY_ICON     (WM_APP + 1)
#define TRAY_TIMER_ID    1
#define TRAY_ICON_UID    1001

#define IDM_STATUS       2000
#define IDM_MODE_AUTO    2001
#define IDM_MODE_ECO     2002
#define IDM_MODE_FULL    2003
#define IDM_PAUSE_15M    2004
#define IDM_PAUSE_60M    2005
#define IDM_PAUSE_MANUAL 2006
#define IDM_TOGGLE_CON   2007
#define IDM_AUTOSTART    2008
#define IDM_EXIT         2009

static int get_exe_and_config_cmd(const char *config_path, wchar_t *out, size_t out_chars) {
    wchar_t exe_path[MAX_PATH];
    DWORD len = GetModuleFileNameW(NULL, exe_path, MAX_PATH);
    if (len == 0 || len >= MAX_PATH) return -1;

    if (config_path && config_path[0]) {
        wchar_t cfg_w[MAX_PATH];
        wchar_t cfg_full[MAX_PATH];
        if (MultiByteToWideChar(CP_UTF8, 0, config_path, -1, cfg_w, MAX_PATH) <= 0) {
            MultiByteToWideChar(CP_ACP, 0, config_path, -1, cfg_w, MAX_PATH);
        }
        if (GetFullPathNameW(cfg_w, MAX_PATH, cfg_full, NULL) == 0) {
            wcsncpy(cfg_full, cfg_w, MAX_PATH - 1);
            cfg_full[MAX_PATH - 1] = L'\0';
        }
        _snwprintf(out, out_chars, L"\"%s\" -c \"%s\" --tray", exe_path, cfg_full);
    } else {
        _snwprintf(out, out_chars, L"\"%s\" --tray", exe_path);
    }
    out[out_chars - 1] = L'\0';
    return 0;
}

int autostart_install(const char *config_path) {
    wchar_t cmd[1024];
    if (get_exe_and_config_cmd(config_path, cmd, 1024) != 0) return -1;

    HKEY hkey = NULL;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, AUTOSTART_REG_PATH, 0, NULL,
                        REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, NULL, &hkey, NULL) != ERROR_SUCCESS) {
        return -1;
    }
    DWORD bytes = (DWORD)((wcslen(cmd) + 1) * sizeof(wchar_t));
    LONG rc = RegSetValueExW(hkey, AUTOSTART_REG_NAME, 0, REG_SZ, (const BYTE *)cmd, bytes);
    RegCloseKey(hkey);
    if (rc == ERROR_SUCCESS) {
        LOG_INFO("[AUTOSTART] Installed HKCU Run entry");
        return 0;
    }
    return -1;
}

int autostart_uninstall(void) {
    HKEY hkey = NULL;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, AUTOSTART_REG_PATH, 0, KEY_SET_VALUE, &hkey) != ERROR_SUCCESS) {
        return 0;
    }
    LONG rc = RegDeleteValueW(hkey, AUTOSTART_REG_NAME);
    RegCloseKey(hkey);
    if (rc == ERROR_SUCCESS || rc == ERROR_FILE_NOT_FOUND) {
        LOG_INFO("[AUTOSTART] Removed HKCU Run entry");
        return 0;
    }
    return -1;
}

int autostart_is_installed(void) {
    HKEY hkey = NULL;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, AUTOSTART_REG_PATH, 0, KEY_QUERY_VALUE, &hkey) != ERROR_SUCCESS) {
        return 0;
    }
    DWORD type = 0, size = 0;
    LONG rc = RegQueryValueExW(hkey, AUTOSTART_REG_NAME, NULL, &type, NULL, &size);
    RegCloseKey(hkey);
    return (rc == ERROR_SUCCESS && type == REG_SZ && size > sizeof(wchar_t)) ? 1 : 0;
}

/* Generate a clean 16x16 anti-aliased status circle icon in memory (zero .ico files needed) */
static HICON create_status_icon(COLORREF fill_rgb, int paused_bars) {
    const int W = 16, H = 16;
    BITMAPV5HEADER bi;
    memset(&bi, 0, sizeof(bi));
    bi.bV5Size        = sizeof(bi);
    bi.bV5Width       = W;
    bi.bV5Height      = -H; /* top-down */
    bi.bV5Planes      = 1;
    bi.bV5BitCount    = 32;
    bi.bV5Compression = BI_BITFIELDS;
    bi.bV5RedMask     = 0x00FF0000;
    bi.bV5GreenMask   = 0x0000FF00;
    bi.bV5BlueMask    = 0x000000FF;
    bi.bV5AlphaMask   = 0xFF000000;

    HDC hdc = GetDC(NULL);
    uint32_t *bits = NULL;
    HBITMAP hColor = CreateDIBSection(hdc, (BITMAPINFO *)&bi, DIB_RGB_COLORS, (void **)&bits, NULL, 0);
    HBITMAP hMask  = CreateBitmap(W, H, 1, 1, NULL);
    ReleaseDC(NULL, hdc);
    if (!hColor || !hMask || !bits) {
        if (hColor) DeleteObject(hColor);
        if (hMask) DeleteObject(hMask);
        return NULL;
    }

    uint32_t r = GetRValue(fill_rgb);
    uint32_t g = GetGValue(fill_rgb);
    uint32_t b = GetBValue(fill_rgb);

    for (int y = 0; y < H; y++) {
        for (int x = 0; x < W; x++) {
            float dx = (x + 0.5f) - 8.0f;
            float dy = (y + 0.5f) - 8.0f;
            float dist = dx * dx + dy * dy;
            uint32_t px = 0x00000000;
            if (dist <= 53.0f) {
                uint32_t cr = r, cg = g, cb = b;
                if (dist > 40.0f) {
                    /* subtle dark rim */
                    cr = cr * 6 / 10;
                    cg = cg * 6 / 10;
                    cb = cb * 6 / 10;
                } else if (paused_bars) {
                    /* crisp white pause bars || */
                    if ((y >= 4 && y <= 11) && ((x >= 5 && x <= 6) || (x >= 9 && x <= 10))) {
                        cr = cg = cb = 245;
                    }
                } else {
                    /* crisp white 'M' glyph inside circle */
                    int is_m = 0;
                    if (y >= 4 && y <= 11 && (x == 4 || x == 11)) is_m = 1;
                    if ((y == 5 && (x == 5 || x == 10)) ||
                        (y == 6 && (x == 6 || x == 9)) ||
                        (y == 7 && (x == 7 || x == 8))) is_m = 1;
                    if (is_m) { cr = cg = cb = 250; }
                }
                px = (0xFFu << 24) | (cr << 16) | (cg << 8) | cb;
            }
            bits[y * W + x] = px;
        }
    }

    ICONINFO ii;
    memset(&ii, 0, sizeof(ii));
    ii.fIcon = TRUE;
    ii.hbmColor = hColor;
    ii.hbmMask = hMask;
    HICON hIcon = CreateIconIndirect(&ii);
    DeleteObject(hColor);
    DeleteObject(hMask);
    return hIcon;
}

struct tray_ctx {
    miner_ctx_t    *miner;
    watchdog_ctx_t *watchdog;
    char            config_path[512];
    tray_exit_cb_t  on_exit;
    HANDLE          thread;
    HANDLE          ready_event;
    HWND            hwnd;
    NOTIFYICONDATAW nid;
    HICON           icon_full;
    HICON           icon_eco;
    HICON           icon_paused;
    int             console_visible;
    int             hide_console_on_start;
    int             last_icon_state;
};

static void tray_update_icon_and_tip(tray_ctx_t *t) {
    if (!t || !t->hwnd) return;
    char reason[64] = {0};
    yield_state_t st = t->watchdog
        ? watchdog_get_state(t->watchdog, reason, sizeof(reason))
        : (yield_state_t)miner_get_yield_state(t->miner);

    double hr = 0.0, watts = 0.0;
    if (t->miner) miner_get_live_stats(t->miner, &hr, &watts);

    HICON target_icon = t->icon_full;
    if (st == YIELD_STATE_ECO) target_icon = t->icon_eco;
    else if (st == YIELD_STATE_PAUSED) target_icon = t->icon_paused;

    wchar_t tip[128];
    if (st == YIELD_STATE_PAUSED) {
        wchar_t rw[64];
        MultiByteToWideChar(CP_UTF8, 0, reason[0] ? reason : "paused", -1, rw, 64);
        _snwprintf(tip, 128, L"XMR-Miner [PAUSED] %s", rw);
    } else if (watts > 0.5) {
        _snwprintf(tip, 128, L"XMR-Miner [%S] %.0f H/s | %.1f W (%.1f H/W)",
                   yield_state_str(st), hr, watts, hr / watts);
    } else {
        _snwprintf(tip, 128, L"XMR-Miner [%S] %.0f H/s", yield_state_str(st), hr);
    }
    tip[127] = L'\0';

    t->nid.uFlags = NIF_TIP | NIF_ICON;
    t->nid.hIcon = target_icon;
    wcsncpy(t->nid.szTip, tip, 127);
    t->nid.szTip[127] = L'\0';
    Shell_NotifyIconW(NIM_MODIFY, &t->nid);
    t->last_icon_state = (int)st;
}

static void tray_show_menu(tray_ctx_t *t) {
    POINT pt;
    GetCursorPos(&pt);

    HMENU menu = CreatePopupMenu();
    if (!menu) return;

    char reason[64] = {0};
    yield_state_t st = t->watchdog
        ? watchdog_get_state(t->watchdog, reason, sizeof(reason))
        : (yield_state_t)miner_get_yield_state(t->miner);
    uint32_t rem_sec = 0;
    yield_override_t ov = t->watchdog
        ? watchdog_get_override(t->watchdog, &rem_sec)
        : YIELD_OVERRIDE_AUTO;

    double hr = 0.0, watts = 0.0;
    if (t->miner) miner_get_live_stats(t->miner, &hr, &watts);

    wchar_t status_line[128];
    if (st == YIELD_STATE_PAUSED) {
        wchar_t rw[64];
        MultiByteToWideChar(CP_UTF8, 0, reason[0] ? reason : "paused", -1, rw, 64);
        _snwprintf(status_line, 128, L"Status: PAUSED (%s)", rw);
    } else if (watts > 0.5) {
        _snwprintf(status_line, 128, L"Status: %S  |  %.0f H/s  |  %.1f W (%.1f H/W)",
                   yield_state_str(st), hr, watts, hr / watts);
    } else {
        _snwprintf(status_line, 128, L"Status: %S  |  %.0f H/s", yield_state_str(st), hr);
    }
    status_line[127] = L'\0';

    AppendMenuW(menu, MF_STRING | MF_DISABLED | MF_GRAYED, IDM_STATUS, status_line);
    AppendMenuW(menu, MF_SEPARATOR, 0, NULL);

    AppendMenuW(menu, MF_STRING | (ov == YIELD_OVERRIDE_AUTO ? MF_CHECKED : 0),
                IDM_MODE_AUTO, L"Auto-Yield (Smart)");
    AppendMenuW(menu, MF_STRING | (ov == YIELD_OVERRIDE_ECO ? MF_CHECKED : 0),
                IDM_MODE_ECO, L"Wymus: ECO (tylko E-cores)");
    AppendMenuW(menu, MF_STRING | (ov == YIELD_OVERRIDE_FULL ? MF_CHECKED : 0),
                IDM_MODE_FULL, L"Wymus: FULL (P+E)");
    AppendMenuW(menu, MF_SEPARATOR, 0, NULL);

    AppendMenuW(menu, MF_STRING, IDM_PAUSE_15M, L"Pauza 15 min");
    AppendMenuW(menu, MF_STRING, IDM_PAUSE_60M, L"Pauza 1 godz.");
    AppendMenuW(menu, MF_STRING | (ov == YIELD_OVERRIDE_PAUSED && rem_sec == 0 ? MF_CHECKED : 0),
                IDM_PAUSE_MANUAL, L"Pauza (reczna)");
    AppendMenuW(menu, MF_SEPARATOR, 0, NULL);

    AppendMenuW(menu, MF_STRING, IDM_TOGGLE_CON,
                t->console_visible ? L"Ukryj konsole" : L"Pokaz konsole");
    AppendMenuW(menu, MF_STRING | (autostart_is_installed() ? MF_CHECKED : 0),
                IDM_AUTOSTART, L"Autostart z Windows");
    AppendMenuW(menu, MF_SEPARATOR, 0, NULL);
    AppendMenuW(menu, MF_STRING, IDM_EXIT, L"Zakoncz");

    SetForegroundWindow(t->hwnd);
    TrackPopupMenu(menu, TPM_RIGHTBUTTON | TPM_BOTTOMALIGN | TPM_LEFTALIGN,
                   pt.x, pt.y, 0, t->hwnd, NULL);
    PostMessageW(t->hwnd, WM_NULL, 0, 0);
    DestroyMenu(menu);
}

static LRESULT CALLBACK tray_wnd_proc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    tray_ctx_t *t = (tray_ctx_t *)GetWindowLongPtrW(hwnd, GWLP_USERDATA);

    switch (msg) {
    case WM_TRAY_ICON:
        if (lParam == WM_RBUTTONUP || lParam == WM_CONTEXTMENU) {
            if (t) tray_show_menu(t);
        } else if (lParam == WM_LBUTTONDBLCLK) {
            if (t) {
                HWND con = GetConsoleWindow();
                if (con) {
                    t->console_visible = !t->console_visible;
                    ShowWindow(con, t->console_visible ? SW_SHOW : SW_HIDE);
                    if (t->console_visible) SetForegroundWindow(con);
                }
            }
        }
        return 0;

    case WM_TIMER:
        if (wParam == TRAY_TIMER_ID && t) {
            tray_update_icon_and_tip(t);
        }
        return 0;

    case WM_COMMAND:
        if (!t) break;
        switch (LOWORD(wParam)) {
        case IDM_MODE_AUTO:
            if (t->watchdog) watchdog_set_override(t->watchdog, YIELD_OVERRIDE_AUTO, 0);
            tray_update_icon_and_tip(t);
            break;
        case IDM_MODE_ECO:
            if (t->watchdog) watchdog_set_override(t->watchdog, YIELD_OVERRIDE_ECO, 0);
            tray_update_icon_and_tip(t);
            break;
        case IDM_MODE_FULL:
            if (t->watchdog) watchdog_set_override(t->watchdog, YIELD_OVERRIDE_FULL, 0);
            tray_update_icon_and_tip(t);
            break;
        case IDM_PAUSE_15M:
            if (t->watchdog) watchdog_set_override(t->watchdog, YIELD_OVERRIDE_PAUSED, 15 * 60);
            tray_update_icon_and_tip(t);
            break;
        case IDM_PAUSE_60M:
            if (t->watchdog) watchdog_set_override(t->watchdog, YIELD_OVERRIDE_PAUSED, 60 * 60);
            tray_update_icon_and_tip(t);
            break;
        case IDM_PAUSE_MANUAL:
            if (t->watchdog) watchdog_set_override(t->watchdog, YIELD_OVERRIDE_PAUSED, 0);
            tray_update_icon_and_tip(t);
            break;
        case IDM_TOGGLE_CON: {
            HWND con = GetConsoleWindow();
            if (con) {
                t->console_visible = !t->console_visible;
                ShowWindow(con, t->console_visible ? SW_SHOW : SW_HIDE);
                if (t->console_visible) SetForegroundWindow(con);
            }
            break;
        }
        case IDM_AUTOSTART:
            if (autostart_is_installed()) autostart_uninstall();
            else autostart_install(t->config_path);
            break;
        case IDM_EXIT:
            if (t->on_exit) t->on_exit();
            PostQuitMessage(0);
            break;
        }
        return 0;

    case WM_QUERYENDSESSION:
        if (t && t->on_exit) t->on_exit();
        return TRUE;

    case WM_CLOSE:
        DestroyWindow(hwnd);
        return 0;

    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

static DWORD WINAPI tray_thread_entry(LPVOID arg) {
    tray_ctx_t *t = (tray_ctx_t *)arg;

    WNDCLASSEXW wc;
    memset(&wc, 0, sizeof(wc));
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = tray_wnd_proc;
    wc.hInstance = GetModuleHandleW(NULL);
    wc.lpszClassName = L"XMRMinerTrayClass";
    RegisterClassExW(&wc);

    t->hwnd = CreateWindowExW(0, wc.lpszClassName, L"XMR-Miner",
                              0, 0, 0, 0, 0, NULL, NULL, wc.hInstance, NULL);
    if (!t->hwnd) {
        SetEvent(t->ready_event);
        return 1;
    }
    SetWindowLongPtrW(t->hwnd, GWLP_USERDATA, (LONG_PTR)t);

    t->icon_full   = create_status_icon(RGB(16, 185, 129), 0);  /* emerald green */
    t->icon_eco    = create_status_icon(RGB(245, 158, 11), 0);  /* amber */
    t->icon_paused = create_status_icon(RGB(107, 114, 128), 1); /* slate gray + || */

    memset(&t->nid, 0, sizeof(t->nid));
    t->nid.cbSize = sizeof(t->nid);
    t->nid.hWnd = t->hwnd;
    t->nid.uID = TRAY_ICON_UID;
    t->nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
    t->nid.uCallbackMessage = WM_TRAY_ICON;
    t->nid.hIcon = t->icon_full;
    wcsncpy(t->nid.szTip, L"XMR-Miner (starting...)", 127);
    Shell_NotifyIconW(NIM_ADD, &t->nid);

    if (t->hide_console_on_start) {
        HWND con = GetConsoleWindow();
        if (con) {
            ShowWindow(con, SW_HIDE);
            t->console_visible = 0;
        }
    } else {
        t->console_visible = 1;
    }

    SetTimer(t->hwnd, TRAY_TIMER_ID, 2000, NULL);
    tray_update_icon_and_tip(t);
    SetEvent(t->ready_event);

    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    KillTimer(t->hwnd, TRAY_TIMER_ID);
    Shell_NotifyIconW(NIM_DELETE, &t->nid);
    if (t->icon_full) DestroyIcon(t->icon_full);
    if (t->icon_eco) DestroyIcon(t->icon_eco);
    if (t->icon_paused) DestroyIcon(t->icon_paused);
    t->icon_full = t->icon_eco = t->icon_paused = NULL;
    t->hwnd = NULL;
    return 0;
}

tray_ctx_t *tray_create(miner_ctx_t *miner, watchdog_ctx_t *watchdog,
                        const char *config_path, tray_exit_cb_t on_exit) {
    tray_ctx_t *t = (tray_ctx_t *)calloc(1, sizeof(tray_ctx_t));
    if (!t) return NULL;
    t->miner = miner;
    t->watchdog = watchdog;
    t->on_exit = on_exit;
    t->last_icon_state = -1;
    if (config_path) {
        snprintf(t->config_path, sizeof(t->config_path), "%s", config_path);
    }
    t->ready_event = CreateEventA(NULL, TRUE, FALSE, NULL);
    return t;
}

int tray_start(tray_ctx_t *tray, int hide_console) {
    if (!tray || tray->thread) return -1;
    tray->hide_console_on_start = hide_console ? 1 : 0;
    ResetEvent(tray->ready_event);
    tray->thread = CreateThread(NULL, 0, tray_thread_entry, tray, 0, NULL);
    if (!tray->thread) return -1;
    WaitForSingleObject(tray->ready_event, 3000);
    return tray->hwnd ? 0 : -1;
}

void tray_stop(tray_ctx_t *tray) {
    if (!tray || !tray->thread) return;
    if (tray->hwnd) {
        PostMessageW(tray->hwnd, WM_CLOSE, 0, 0);
    }
    WaitForSingleObject(tray->thread, 3000);
    CloseHandle(tray->thread);
    tray->thread = NULL;
}

void tray_destroy(tray_ctx_t *tray) {
    if (!tray) return;
    tray_stop(tray);
    if (tray->ready_event) CloseHandle(tray->ready_event);
    free(tray);
}

#endif /* _WIN32 */
