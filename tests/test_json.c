/*
 * Unit tests for the stratum JSON parser/writer (json.c).
 *
 * Exercises the parser directly with well-formed and malformed input,
 * and the writer's string escaping. All checks are asserted; the binary
 * returns non-zero on any failure.
 */
#include "stratum/json.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int checks = 0;
static int failures = 0;

#define CHECK(cond) do { \
    checks++; \
    if (!(cond)) { \
        printf("  [FAIL] %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        failures++; \
    } \
} while (0)

static const json_token_t *parse_and_get(const char *src, const char *key) {
    static json_parser_t jp;
    if (json_parse(&jp, src, strlen(src)) != 0) return NULL;
    return json_get(&jp, key);
}

static void test_valid_object(void) {
    const char *src = "{\"id\":1,\"method\":\"submit\",\"result\":true}";
    json_parser_t jp;
    CHECK(json_parse(&jp, src, strlen(src)) == 0);

    const json_token_t *id = json_get(&jp, "id");
    CHECK(id != NULL && id->type == JSON_INT);

    const json_token_t *m = json_get(&jp, "method");
    CHECK(m != NULL && m->type == JSON_STRING);
    CHECK((size_t)(m->end - m->start) == 6 && strncmp(m->start, "submit", 6) == 0);

    const json_token_t *r = json_get(&jp, "result");
    CHECK(r != NULL && r->type == JSON_BOOL);
    CHECK((r->end - r->start) == 4 && strncmp(r->start, "true", 4) == 0);

    /* missing key */
    CHECK(json_get(&jp, "nope") == NULL);
}

static void test_nested_object_and_array(void) {
    const char *src = "{\"result\":{\"id\":\"sid\",\"job\":{\"blob\":\"ab\",\"algo\":\"rx/0\"}},"
                      "\"arr\":[1,2,3]}";
    json_parser_t jp;
    CHECK(json_parse(&jp, src, strlen(src)) == 0);

    const json_token_t *result = json_get(&jp, "result");
    CHECK(result != NULL && result->type == JSON_OBJECT);

    const json_token_t *jid = json_get_in(&jp, result, "id");
    CHECK(jid != NULL && jid->type == JSON_STRING);

    const json_token_t *job = json_get_in(&jp, result, "job");
    CHECK(job != NULL && job->type == JSON_OBJECT);

    const json_token_t *blob = json_get_in(&jp, job, "blob");
    CHECK(blob != NULL && blob->type == JSON_STRING);

    const json_token_t *arr = json_get(&jp, "arr");
    CHECK(arr != NULL && arr->type == JSON_ARRAY && arr->size == 3);

    const json_token_t *e1 = json_child(&jp, arr, 0);
    const json_token_t *e2 = json_child(&jp, arr, 1);
    const json_token_t *e3 = json_child(&jp, arr, 2);
    const json_token_t *e4 = json_child(&jp, arr, 3);
    CHECK(e1 != NULL && e2 != NULL && e3 != NULL && e4 == NULL);
    CHECK(e1->type == JSON_INT);
}

static void test_empty_input(void) {
    json_parser_t jp;
    CHECK(json_parse(&jp, "", 0) == -1);
    CHECK(parse_and_get("{}", "x") == NULL);  /* valid empty object, no keys */
}

static void test_empty_collections(void) {
    json_parser_t jp;
    CHECK(json_parse(&jp, "{}", 2) == 0);
    CHECK(json_parse(&jp, "[]", 2) == 0);
}

static void test_malformed(void) {
    json_parser_t jp;
    /* unterminated string */
    CHECK(json_parse(&jp, "{\"k\":\"oops", strlen("{\"k\":\"oops")) == -1);
    /* unclosed object */
    CHECK(json_parse(&jp, "{\"k\":1", strlen("{\"k\":1")) == -1);
    /* unclosed array */
    CHECK(json_parse(&jp, "[1,2", strlen("[1,2")) == -1);
    /* missing colon */
    CHECK(json_parse(&jp, "{\"k\" 1}", strlen("{\"k\" 1}")) == -1);
    /* garbage */
    CHECK(json_parse(&jp, "xyz", 3) == -1);
    /* trailing comma in object */
    CHECK(json_parse(&jp, "{\"a\":1,}", strlen("{\"a\":1,}")) == -1);
}

static void test_number_types(void) {
    const char *src = "{\"i\":42,\"f\":3.14,\"neg\":-7}";
    json_parser_t jp;
    CHECK(json_parse(&jp, src, strlen(src)) == 0);
    const json_token_t *i = json_get(&jp, "i");
    CHECK(i != NULL && i->type == JSON_INT);
    const json_token_t *f = json_get(&jp, "f");
    CHECK(f != NULL && f->type == JSON_FLOAT);
    const json_token_t *n = json_get(&jp, "neg");
    CHECK(n != NULL && n->type == JSON_INT);
}

static void test_null_and_false(void) {
    const char *src = "{\"a\":null,\"b\":false}";
    json_parser_t jp;
    CHECK(json_parse(&jp, src, strlen(src)) == 0);
    const json_token_t *a = json_get(&jp, "a");
    CHECK(a != NULL && a->type == JSON_NULL);
    const json_token_t *b = json_get(&jp, "b");
    CHECK(b != NULL && b->type == JSON_BOOL);
    CHECK((b->end - b->start) == 5 && strncmp(b->start, "false", 5) == 0);
}

static void test_string_with_escapes(void) {
    /* parser keeps raw bytes between quotes; escaped quote handled by skip */
    const char *src = "{\"k\":\"a\\\"b\"}";
    json_parser_t jp;
    CHECK(json_parse(&jp, src, strlen(src)) == 0);
    const json_token_t *k = json_get(&jp, "k");
    CHECK(k != NULL && k->type == JSON_STRING);
}

static void test_writer_string_escape(void) {
    json_writer_t w;
    json_writer_init(&w);
    json_object_start(&w);
    json_key(&w, "k");
    /* value containing quote, backslash, and a control char */
    json_string(&w, "a\"b\\c\x01d");
    json_object_end(&w);

    /* round-trip: the written JSON must parse back */
    json_parser_t jp;
    CHECK(json_parse(&jp, w.buf, w.len) == 0);
    const json_token_t *k = json_get(&jp, "k");
    CHECK(k != NULL && k->type == JSON_STRING);

    json_writer_free(&w);
}

static void test_token_overflow(void) {
    /* Build a deeply-arrayed structure to exceed JSON_MAX_TOKENS (512).
       The parser must reject it rather than overflow its token table. */
    char buf[8192];
    int pos = 0;
    /* 600 nested single-element arrays -> 600+ tokens, exceeds 512 */
    for (int i = 0; i < 600; i++) pos += snprintf(buf + pos, sizeof(buf) - pos, "[1,");
    /* close with enough brackets */
    buf[pos++] = '1';
    for (int i = 0; i < 600; i++) {
        if (pos < (int)sizeof(buf) - 2) buf[pos++] = ']';
    }
    buf[pos] = '\0';
    json_parser_t jp;
    CHECK(json_parse(&jp, buf, strlen(buf)) == -1);
}

int main(void) {
    printf("[TEST] JSON parser/writer\n");
    test_valid_object();
    test_nested_object_and_array();
    test_empty_input();
    test_empty_collections();
    test_malformed();
    test_number_types();
    test_null_and_false();
    test_string_with_escapes();
    test_writer_string_escape();
    test_token_overflow();

    printf("[TEST] %d checks, %d failures\n", checks, failures);
    printf("[TEST] %s\n", failures == 0 ? "PASS" : "FAIL");
    return failures == 0 ? 0 : 1;
}
