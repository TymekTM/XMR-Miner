#pragma once

#include "common/osdep.h"

typedef struct miner_ctx miner_ctx_t;
typedef struct watchdog_ctx watchdog_ctx_t;
typedef struct tray_ctx tray_ctx_t;

typedef void (*tray_exit_cb_t)(void);

/* User-space Windows autostart via HKCU\Software\Microsoft\Windows\CurrentVersion\Run */
int autostart_install(const char *config_path);
int autostart_uninstall(void);
int autostart_is_installed(void);

/* Windows System Tray icon (runs its own lightweight Win32 message thread) */
tray_ctx_t *tray_create(miner_ctx_t *miner, watchdog_ctx_t *watchdog,
                        const char *config_path, tray_exit_cb_t on_exit);
int  tray_start(tray_ctx_t *tray, int hide_console);
void tray_stop(tray_ctx_t *tray);
void tray_destroy(tray_ctx_t *tray);
