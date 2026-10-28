#pragma once

/* Base version of the PS5 Linux Launcher content. */
#define WKAL_VERSION "0.1.0"

/* Full build version */
#include "wkali_version.h"

/* Network Settings */
#define WKALI_PORT 18181

/* Title ID of the installed homescreen app ("PS5 Linux Launcher") */
#define WKAL_TITLE_ID "PS5L00001"

/* Process identity */
#define WKALI_THREAD_NAME "ps5ll.elf"

/* Routes */
#define ROUTE_INDEX "/"
#define ROUTE_INDEX_HTML "/index.html"
#define ROUTE_CACHE_MANIFEST "/cache.appcache"
#define ROUTE_INSTALL "/install"
#define ROUTE_VERSION "/version"
#define ROUTE_CLEAR_WEBKIT_DATA "/clear-webkit-data"
#define ROUTE_EXIT "/exit"

/* Native platform helpers are owned by remote-loader. */
#include "installer_support.h"
