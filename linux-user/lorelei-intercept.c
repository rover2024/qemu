/*
 * Lorelei address-based interception (Slice 1).
 *
 * Reads a JSON sidecar next to the guest executable that maps a marked guest
 * entry address to a redirect target address. The i386 translator consults
 * this table so that a stripped, statically-linked library function can be
 * diverted to a Lorelei thunk instead of being translated.
 *
 * Sidecar format (<exec_path>.lorelei.json):
 *   { "intercepts": [ { "entry": "0x401c60", "target": "0x402000" } ] }
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "qemu/osdep.h"
#include "qemu/error-report.h"
#include "qobject/qjson.h"
#include "qobject/qdict.h"
#include "qobject/qlist.h"
#include "lorelei-intercept.h"

#define LORE_MAX_REDIRS 256

typedef struct {
    uint64_t entry;
    uint64_t target;
} LoreRedir;

static LoreRedir lore_redirs[LORE_MAX_REDIRS];
static int lore_n_redirs;

uint64_t lorelei_redirect_lookup(uint64_t pc)
{
    for (int i = 0; i < lore_n_redirs; i++) {
        if (lore_redirs[i].entry == pc) {
            return lore_redirs[i].target;
        }
    }
    return 0;
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
    const QListEntry *ent;

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

    QLIST_FOREACH_ENTRY(list, ent) {
        QDict *it = qobject_to(QDict, qlist_entry_obj(ent));
        const char *es, *ts;
        if (!it) {
            continue;
        }
        es = qdict_get_try_str(it, "entry");
        ts = qdict_get_try_str(it, "target");
        if (!es || !ts) {
            continue;
        }
        if (lore_n_redirs < LORE_MAX_REDIRS) {
            lore_redirs[lore_n_redirs].entry = strtoull(es, NULL, 0);
            lore_redirs[lore_n_redirs].target = strtoull(ts, NULL, 0);
            lore_n_redirs++;
        }
    }
    qobject_unref(root);
    warn_report("lorelei: loaded %d redirect(s) from %s", lore_n_redirs, path);
}
