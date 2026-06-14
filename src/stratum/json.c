#include "json.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static char json_buf_grow(json_writer_t *w, size_t extra) {
    if (w->len + extra >= w->cap) {
        size_t new_cap = w->cap ? w->cap * 2 : 4096;
        while (new_cap < w->len + extra + 1) new_cap *= 2;
        char *nb = (char *)realloc(w->buf, new_cap);
        if (!nb) return 0;
        w->buf = nb;
        w->cap = new_cap;
    }
    return 1;
}

static void json_raw(json_writer_t *w, const char *s) {
    size_t slen = strlen(s);
    if (!json_buf_grow(w, slen)) return;
    memcpy(w->buf + w->len, s, slen);
    w->len += slen;
}

void json_writer_init(json_writer_t *w) { memset(w, 0, sizeof(*w)); }
void json_writer_reset(json_writer_t *w) { w->len = 0; }
void json_writer_free(json_writer_t *w) { free(w->buf); w->buf = NULL; w->cap = 0; w->len = 0; }

void json_object_start(json_writer_t *w) { json_raw(w, "{"); }
void json_object_end(json_writer_t *w) { json_raw(w, "}"); }
void json_array_start(json_writer_t *w) { json_raw(w, "["); }
void json_array_end(json_writer_t *w) { json_raw(w, "]"); }

void json_key(json_writer_t *w, const char *key) {
    char buf[512];
    snprintf(buf, sizeof(buf), "\"%s\":", key);
    json_raw(w, buf);
}

void json_string(json_writer_t *w, const char *val) {
    char buf[4096];
    int pos = 0;
    buf[pos++] = '"';
    for (const char *s = val; *s && pos < (int)sizeof(buf) - 6; s++) {
        if (*s == '"' || *s == '\\') {
            buf[pos++] = '\\';
            buf[pos++] = *s;
        } else if (*s >= 0 && *s < 0x20) {
            pos += snprintf(buf + pos, sizeof(buf) - pos, "\\u%04x", (unsigned char)*s);
        } else {
            buf[pos++] = *s;
        }
    }
    buf[pos++] = '"';
    buf[pos] = '\0';
    json_raw(w, buf);
}

void json_int(json_writer_t *w, i64 val) {
    char buf[64];
    snprintf(buf, sizeof(buf), "%lld", (long long)val);
    json_raw(w, buf);
}

void json_null(json_writer_t *w) { json_raw(w, "null"); }

static const char *skip_ws(const char *p) {
    while (*p && (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')) p++;
    return p;
}

static const char *parse_string(const char *js, const char *end, json_token_t *t) {
    if (*js != '"') return NULL;
    js++;
    t->start = js;
    while (js < end && *js != '"') {
        if (*js == '\\') js++;
        js++;
    }
    if (js >= end) return NULL;
    t->end = js;
    t->type = JSON_STRING;
    return js + 1;
}

static const char *parse_value(const char *js, const char *end, json_token_t *t, json_parser_t *p, int depth);

static const char *parse_number(const char *js, const char *end, json_token_t *t) {
    t->start = js;
    if (*js == '-') js++;
    while (js < end && *js >= '0' && *js <= '9') js++;
    if (js < end && *js == '.') {
        js++;
        while (js < end && *js >= '0' && *js <= '9') js++;
        t->type = JSON_FLOAT;
    } else {
        t->type = JSON_INT;
    }
    t->end = js;
    return js;
}

static const char *parse_object(const char *js, const char *end, json_token_t *t, json_parser_t *p, int depth) {
    if (*js != '{') return NULL;
    js++;
    t->start = js;
    t->type = JSON_OBJECT;
    int count = 0;
    while (js < end) {
        js = skip_ws(js);
        if (*js == '}') { js++; t->end = js; t->size = count; return js; }
        if (*js == ',') js++;
        js = skip_ws(js);

        if (p->count < JSON_MAX_TOKENS) {
            json_token_t *key = &p->tokens[p->count++];
            js = parse_string(js, end, key);
            if (!js) return NULL;
            key->parent = (int)(t - p->tokens);
        } else {
            json_token_t tmp;
            js = parse_string(js, end, &tmp);
            if (!js) return NULL;
        }

        js = skip_ws(js);
        if (*js != ':') return NULL;
        js++;

        js = skip_ws(js);
        if (p->count < JSON_MAX_TOKENS) {
            json_token_t *child = &p->tokens[p->count++];
            js = parse_value(js, end, child, p, depth + 1);
            if (!js) return NULL;
            child->parent = (int)(t - p->tokens);
            count++;
        } else {
            return NULL;
        }
    }
    return NULL;
}

static const char *parse_array(const char *js, const char *end, json_token_t *t, json_parser_t *p, int depth) {
    if (*js != '[') return NULL;
    js++;
    t->start = js;
    t->type = JSON_ARRAY;
    int count = 0;
    while (js < end) {
        js = skip_ws(js);
        if (*js == ']') { js++; t->end = js; t->size = count; return js; }
        if (*js == ',') js++;
        js = skip_ws(js);

        if (p->count < JSON_MAX_TOKENS) {
            json_token_t *child = &p->tokens[p->count++];
            js = parse_value(js, end, child, p, depth + 1);
            if (!js) return NULL;
            child->parent = (int)(t - p->tokens);
            count++;
        } else {
            return NULL;
        }
    }
    return NULL;
}

static const char *parse_value(const char *js, const char *end, json_token_t *t, json_parser_t *p, int depth) {
    if (depth > JSON_MAX_DEPTH) return NULL;
    js = skip_ws(js);
    if (js >= end) return NULL;

    if (*js == '"') return parse_string(js, end, t);
    if (*js == '{') return parse_object(js, end, t, p, depth);
    if (*js == '[') return parse_array(js, end, t, p, depth);
    if (*js == 't') {
        if (js + 3 < end && js[1] == 'r' && js[2] == 'u' && js[3] == 'e') {
            t->type = JSON_BOOL; t->start = js; t->end = js + 4; return js + 4;
        }
        return NULL;
    }
    if (*js == 'f') {
        if (js + 4 < end && js[1] == 'a' && js[2] == 'l' && js[3] == 's' && js[4] == 'e') {
            t->type = JSON_BOOL; t->start = js; t->end = js + 5; return js + 5;
        }
        return NULL;
    }
    if (*js == 'n') {
        if (js + 3 < end && js[1] == 'u' && js[2] == 'l' && js[3] == 'l') {
            t->type = JSON_NULL; t->start = js; t->end = js + 4; return js + 4;
        }
        return NULL;
    }
    if (*js == '-' || (*js >= '0' && *js <= '9')) return parse_number(js, end, t);
    return NULL;
}

int json_parse(json_parser_t *p, const char *js, size_t len) {
    memset(p, 0, sizeof(*p));
    if (len == 0) return -1;
    const char *end = js + len;
    if (p->count < JSON_MAX_TOKENS) {
        const char *r = parse_value(js, end, &p->tokens[p->count++], p, 1);
        if (!r) return -1;
        return 0;
    }
    return -1;
}

const json_token_t *json_get(const json_parser_t *p, const char *key) {
    if (!p || !p->tokens || !key) return NULL;
    size_t klen = strlen(key);
    for (int i = 1; i < p->count; i++) {
        if (p->tokens[i].parent != 0) continue;
        if (p->tokens[i].type != JSON_STRING) continue;
        size_t tlen = (size_t)(p->tokens[i].end - p->tokens[i].start);
        if (tlen == klen && strncmp(p->tokens[i].start, key, tlen) == 0) {
            for (int j = i + 1; j < p->count; j++) {
                if (p->tokens[j].parent == 0)
                    return &p->tokens[j];
            }
        }
    }
    return NULL;
}

const json_token_t *json_get_in(const json_parser_t *p, const json_token_t *obj, const char *key) {
    if (!obj || obj->type != JSON_OBJECT) return NULL;
    int parent_idx = (int)(obj - p->tokens);
    size_t klen = strlen(key);
    for (int i = 0; i < p->count; i++) {
        if (p->tokens[i].parent == parent_idx && p->tokens[i].type == JSON_STRING) {
            size_t tlen = (size_t)(p->tokens[i].end - p->tokens[i].start);
            if (tlen == klen && strncmp(p->tokens[i].start, key, tlen) == 0) {
                for (int j = i + 1; j < p->count; j++) {
                    if (p->tokens[j].parent == parent_idx)
                        return &p->tokens[j];
                }
            }
        }
    }
    return NULL;
}

const json_token_t *json_child(const json_parser_t *p, const json_token_t *parent, int index) {
    if (!parent) return NULL;
    int parent_idx = (int)(parent - p->tokens);
    int found = 0;
    for (int i = parent_idx + 1; i < p->count; i++) {
        if (p->tokens[i].parent == parent_idx) {
            if (found == index) return &p->tokens[i];
            found++;
        }
    }
    return NULL;
}
