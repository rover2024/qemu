/*
 * Lorelei address-based interception (slice 2).
 *
 * Sidecar <exec_path>.lorelei.json maps a marked guest entry address to a
 * thunk id:  { "intercepts": [ { "entry": "0x401cb0", "id": "crc32" } ] }
 * A preloaded guest thunk registers "id -> its runtime address" via a magic
 * syscall; the i386 translator then diverts the marked entry to that address.
 * The thunk forwards to the host library through another magic syscall handled
 * by lorelei_host_call().
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "qemu/osdep.h"
#include "qemu/error-report.h"
#include "qobject/qjson.h"
#include "qobject/qdict.h"
#include "qobject/qlist.h"
#include "lorelei-intercept.h"
#include <dlfcn.h>

#define LORE_MAX 256

typedef struct {
    uint64_t entry;
    char id[64];
    uint64_t target;   /* resolved thunk address, 0 until registered */
} LoreRedir;

static LoreRedir tbl[LORE_MAX];
static int lore_n;

uint64_t lorelei_redirect_lookup(uint64_t pc)
{
    for (int i = 0; i < lore_n; i++) {
        if (tbl[i].entry == pc) {
            return tbl[i].target;   /* 0 while unresolved -> no redirect yet */
        }
    }
    return 0;
}

void lorelei_register_thunk(const char *id, uint64_t addr)
{
    int hit = 0;
    for (int i = 0; i < lore_n; i++) {
        if (strcmp(tbl[i].id, id) == 0) {
            tbl[i].target = addr;
            hit++;
        }
    }
    warn_report("lorelei: register '%s' -> 0x%" PRIx64 " (%d entries)",
                id, addr, hit);
}

uint64_t lorelei_host_call(const char *lib, const char *name,
                          int argc, const uint64_t *argv)
{
    static struct { char lib[64]; void *h; } cache[16];
    static int nc;
    void *h = NULL, *fn;
    uint64_t a[6] = {0, 0, 0, 0, 0, 0};
    typedef uint64_t (*fn6)(uint64_t, uint64_t, uint64_t,
                            uint64_t, uint64_t, uint64_t);

    for (int i = 0; i < nc; i++) {
        if (strcmp(cache[i].lib, lib) == 0) { h = cache[i].h; break; }
    }
    if (!h) {
        h = dlopen(lib, RTLD_NOW | RTLD_GLOBAL);
        if (!h) {
            warn_report("lorelei: dlopen %s failed: %s", lib, dlerror());
            return 0;
        }
        if (nc < 16) {
            g_strlcpy(cache[nc].lib, lib, sizeof(cache[nc].lib));
            cache[nc].h = h; nc++;
        }
    }
    fn = dlsym(h, name);
    if (!fn) {
        warn_report("lorelei: dlsym %s in %s failed", name, lib);
        return 0;
    }
    for (int i = 0; i < argc && i < 6; i++) {
        a[i] = argv[i];
    }
    return ((fn6)fn)(a[0], a[1], a[2], a[3], a[4], a[5]);
}

void lorelei_intercept_init(const char *exec_path)
{
    g_autofree char *path = g_strdup_printf("%s.lorelei.json", exec_path);
    g_autofree char *buf = NULL;
    gsize len = 0;
    GError *gerr = NULL;
    QObject *root;
    QDict *top;
    QList *list;
    const QListEntry *it;

    if (!g_file_test(path, G_FILE_TEST_EXISTS)) {
        return;
    }
    if (!g_file_get_contents(path, &buf, &len, &gerr)) {
        warn_report("lorelei: cannot read %s: %s", path, gerr->message);
        g_error_free(gerr);
        return;
    }

    root = qobject_from_json(buf, NULL);
    top = root ? qobject_to(QDict, root) : NULL;
    list = top ? qdict_get_qlist(top, "intercepts") : NULL;
    if (!list) {
        warn_report("lorelei: %s has no \"intercepts\" array", path);
        qobject_unref(root);
        return;
    }

    QLIST_FOREACH_ENTRY(list, it) {
        QDict *d = qobject_to(QDict, qlist_entry_obj(it));
        const char *es, *id;
        if (!d) {
            continue;
        }
        es = qdict_get_try_str(d, "entry");
        id = qdict_get_try_str(d, "id");
        if (!es || !id) {
            continue;
        }
        if (lore_n < LORE_MAX) {
            tbl[lore_n].entry = strtoull(es, NULL, 0);
            g_strlcpy(tbl[lore_n].id, id, sizeof(tbl[lore_n].id));
            tbl[lore_n].target = 0;
            lore_n++;
        }
    }
    qobject_unref(root);
    warn_report("lorelei: loaded %d intercept(s) from %s", lore_n, path);
}
