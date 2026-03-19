#pragma once

#include "common/osdep.h"

#define JSON_MAX_DEPTH 16
#define JSON_MAX_TOKENS 512

typedef enum {
    JSON_NULL,
    JSON_BOOL,
    JSON_INT,
    JSON_FLOAT,
    JSON_STRING,
    JSON_ARRAY,
    JSON_OBJECT,
} json_type_t;

typedef struct {
    json_type_t type;
    const char *start;
    const char *end;
    int size;
    int parent;
} json_token_t;

typedef struct {
    json_token_t tokens[JSON_MAX_TOKENS];
    int count;
} json_parser_t;

int json_parse(json_parser_t *p, const char *js, size_t len);
const json_token_t *json_get(const json_parser_t *p, const char *key);
const json_token_t *json_get_in(const json_parser_t *p, const json_token_t *obj, const char *key);
const json_token_t *json_child(const json_parser_t *p, const json_token_t *parent, int index);

typedef struct {
    char *buf;
    size_t len;
    size_t cap;
} json_writer_t;

void json_writer_init(json_writer_t *w);
void json_writer_reset(json_writer_t *w);
void json_writer_free(json_writer_t *w);
void json_object_start(json_writer_t *w);
void json_object_end(json_writer_t *w);
void json_array_start(json_writer_t *w);
void json_array_end(json_writer_t *w);
void json_key(json_writer_t *w, const char *key);
void json_string(json_writer_t *w, const char *val);
void json_int(json_writer_t *w, i64 val);
void json_null(json_writer_t *w);
