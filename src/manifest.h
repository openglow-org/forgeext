/*
 * manifest.h - a package's manifest.json, parsed and held to the schema
 * Copyright 2026 514 LLC d/b/a OpenGlow
 * Written by Scott Wiederhold
 * SPDX-License-Identifier: MIT
 *
 * The manifest is the one thing a package says about itself, and every
 * word of it comes from outside. The parser is strict on purpose: an
 * unknown key, a duplicate capability, or a field of the wrong type is a
 * refusal with words, never a default, so that a typo cannot silently
 * drop a capability the operator was meant to see.
 */
#ifndef FORGEEXT_MANIFEST_H
#define FORGEEXT_MANIFEST_H

#include <stddef.h>

#include "caps.h"

#define MANIFEST_SCHEMA      1
#define MANIFEST_MAX_BYTES   (64 * 1024)
#define MANIFEST_MAX_CAPS    32
#define MANIFEST_MAX_ARGS    16
#define MANIFEST_MAX_LIST    16

/* A package's own settings, declared here and kept by the host
 * (settings.h). The manifest is the schema: what the keys are, what a
 * value may be, and what it is before anybody sets it. */
#define MANIFEST_MAX_SETTINGS 16
#define SETTING_NAME_MAX      33
#define SETTING_TEXT_MAX      129       /* the longest a string value may be declared to be, plus the NUL */
#define SETTING_LABEL_MAX     49
#define SETTING_CHOICE_MAX    33
#define SETTING_CHOICES_MAX   6

/* The extension API this daemon serves. 0.x carries no stability
 * promise: a package names the exact minor it was built for. */
#define EXT_API_MAJOR 0
#define EXT_API_MINOR 1

typedef enum {
    RUNTIME_DATA = 0,       /* nothing executes */
    RUNTIME_UI,             /* runs in the operator's browser */
    RUNTIME_SHELL,          /* /bin/sh <exec> */
    RUNTIME_NATIVE,         /* <exec>, a static ARMv7 hard-float binary */
    RUNTIME_PYTHON,         /* python3 <exec>, inside the release image's module list */
} manifest_runtime_t;

typedef enum {
    SETTING_STRING = 0,
    SETTING_NUMBER,
    SETTING_BOOL,
    SETTING_CHOICE,
} setting_type_t;

typedef struct {
    char name[SETTING_NAME_MAX];        /* a lower-case word: [a-z][a-z0-9_]* */
    char label[SETTING_LABEL_MAX];      /* what the operator is shown; the name when it says nothing */
    setting_type_t type;
    char text[SETTING_TEXT_MAX];        /* the default of a string or a choice */
    double number;                      /* the default of a number */
    int boolean;                        /* the default of a bool */
    double min, max;                    /* a number's bounds */
    int has_min, has_max;
    size_t text_max;                    /* a string's longest value: 128 unless it says otherwise */
    char choices[SETTING_CHOICES_MAX][SETTING_CHOICE_MAX];
    int nchoices;
} setting_t;

typedef struct {
    char id[64];
    char name[65];
    char version[33];
    char description[257];
    char author[129];
    char license[65];
    char homepage[257];
    int api_major, api_minor;
    char core_min[33], core_max[33];
    manifest_runtime_t runtime;
    char exec[193];                                 /* relative, inside the package */
    char args[MANIFEST_MAX_ARGS][129];
    int nargs;
    int mode_grbl, mode_cloud;
    char caps[MANIFEST_MAX_CAPS][CAP_MAX_LEN];
    int ncaps;
    char conflicts[MANIFEST_MAX_LIST][64];
    int nconflicts;
    setting_t settings[MANIFEST_MAX_SETTINGS];
    int nsettings;
} manifest_t;

/* Parse and check JSON text: 0, or -1 with the words in err. */
int manifest_parse(const char *text, size_t len, manifest_t *m, char *err, size_t elen);

/* The same from a file (refused above MANIFEST_MAX_BYTES). */
int manifest_load(const char *path, manifest_t *m, char *err, size_t elen);

int manifest_id_ok(const char *id);
int manifest_version_ok(const char *v);
const char *manifest_runtime_name(manifest_runtime_t r);
int manifest_has_service(const manifest_t *m);
int manifest_has_cap(const manifest_t *m, const char *cap);
/* The declared setting of that name, or NULL. */
const setting_t *manifest_setting(const manifest_t *m, const char *name);

/* Is the id inside the namespace only the official key may sign? */
int manifest_id_reserved(const char *id);

/* semver-style comparison of "MAJOR.MINOR.PATCH[-pre]": <0, 0, >0. A
 * pre-release sorts before its release. */
int manifest_version_cmp(const char *a, const char *b);

#endif
