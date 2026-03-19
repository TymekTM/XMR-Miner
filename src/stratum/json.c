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
    char buf[2048];
    snprintf(buf, sizeof(buf), "\"%s\"", val);
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

static const char *parse_value(const char *js, const char *end, json_token_t *t, json_parser_t *p);

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

static const char *parse_object(const char *js, const char *end, json_token_t *t, json_parser_t *p) {
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
            js = parse_value(js, end, child, p);
            if (!js) return NULL;
            child->parent = (int)(t - p->tokens);
            count++;
        } else {
            return NULL;
        }
    }
    return NULL;
}

static const char *parse_array(const char *js, const char *end, json_token_t *t, json_parser_t *p) {
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
            js = parse_value(js, end, child, p);
            if (!js) return NULL;
            child->parent = (int)(t - p->tokens);
            count++;
        } else {
            return NULL;
        }
    }
    return NULL;
}

static const char *parse_value(const char *js, const char *end, json_token_t *t, json_parser_t *p) {
    js = skip_ws(js);
    if (js >= end) return NULL;

    if (*js == '"') return parse_string(js, end, t);
    if (*js == '{') return parse_object(js, end, t, p);
    if (*js == '[') return parse_array(js, end, t, p);
    if (*js == 't') { t->type = JSON_BOOL; t->start = js; t->end = js + 4; return js + 4; }
    if (*js == 'f') { t->type = JSON_BOOL; t->start = js; t->end = js + 5; return js + 5; }
    if (*js == 'n') { t->type = JSON_NULL; t->start = js; t->end = js + 4; return js + 4; }
    if (*js == '-' || (*js >= '0' && *js <= '9')) return parse_number(js, end, t);
    return NULL;
}

int json_parse(json_parser_t *p, const char *js, size_t len) {
    memset(p, 0, sizeof(*p));
    if (len == 0) return -1;
    const char *end = js + len;
    if (p->count < JSON_MAX_TOKENS) {
        const char *r = parse_value(js, end, &p->tokens[p->count++], p);
        if (!r) return -1;
        return 0;
    }
    return -1;
}

const json_token_t *json_get(const json_parser_t *p, const char *key) {
    for (int i = 0; i < p->count; i++) {
        const json_token_t *t = &p->tokens[i];
        if (t->type == JSON_OBJECT) {
            int idx = i + 1;
            for (int j = 0; j < t->size; j++) {
                if (idx + j * 2 >= p->count) break;
                const json_token_t *child = &p->tokens[idx + j * 2];
                if (child->type == JSON_STRING &&
                    (size_t)(child->end - child->start) == strlen(key) &&
                    strncmp(child->start, key, child->end - child->start) == 0) {
                    return &p->tokens[idx + j * 2 + 1];
                }
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
