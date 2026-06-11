#include "stratum/stratum.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int failures = 0;

static void check(int condition, const char *name) {
    printf("[%s] %s\n", condition ? "PASS" : "FAIL", name);
    if (!condition) failures++;
}

int main(void) {
    char reason[128];
    uint64_t expected = UINT64_MAX / (UINT32_MAX / UINT64_C(0x00068db8));

    check(stratum_parse_target("b88d0600") == expected,
          "4-byte little-endian Monero target");
    check(stratum_parse_target("8877665544332211") == UINT64_C(0x1122334455667788),
          "8-byte little-endian Monero target");

    check(stratum_classify_submit_response(
              "{\"id\":2,\"error\":null,\"result\":{\"status\":\"OK\"}}",
              reason, sizeof(reason)) == 1,
          "Monero status OK accepted");
    check(stratum_classify_submit_response(
              "{\"id\":2,\"error\":null,\"result\":true}",
              reason, sizeof(reason)) == 1,
          "boolean true accepted");
    check(stratum_classify_submit_response(
              "{\"id\":2,\"error\":null,\"result\":false}",
              reason, sizeof(reason)) == 0,
          "boolean false rejected");
    check(stratum_classify_submit_response(
              "{\"id\":2,\"error\":{\"code\":-1,\"message\":\"Low difficulty share\"}}",
              reason, sizeof(reason)) == 0 &&
          strcmp(reason, "Low difficulty share") == 0,
          "object error rejected with reason");
    check(stratum_classify_submit_response(
              "{\"id\":2,\"error\":[-1,\"Duplicate share\"],\"result\":null}",
              reason, sizeof(reason)) == 0 &&
          strcmp(reason, "Duplicate share") == 0,
          "array error rejected with reason");

    printf("%s: %d failures\n", failures ? "[FAIL]" : "[PASS]", failures);
    return failures ? 1 : 0;
}
