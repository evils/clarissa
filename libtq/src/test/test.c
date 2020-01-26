#include <libtq/test.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

typedef struct test_record_t {
  tq_test_fn_t test_fn;
  char* name;
} test_record_t;

static test_record_t *registered_tests = NULL;
static size_t registered_tests_cap = 0, registered_tests_len = 0;

void tq_test_register(tq_test_fn_t test_fn, const char* name) {
  if (registered_tests_len + 1 > registered_tests_cap) {
    if (registered_tests_cap == 0) {
      registered_tests_cap = 16;
    } else {
      registered_tests_cap *= 2;
    }

    registered_tests = realloc(registered_tests, registered_tests_cap * sizeof(*registered_tests));
  }

  registered_tests[registered_tests_len].test_fn = test_fn;
  registered_tests[registered_tests_len].name = strdup(name);
  registered_tests_len++;
}

void tq_test_run() {
  printf("TAP version 13\n"
	 "1..%zd\n", registered_tests_len);
  for (size_t i = 0; i < registered_tests_len; i++) {
    test_record_t *test = &registered_tests[i];
    if(test->test_fn()) {
      printf("ok %zd %s\n", i+1, test->name);
    } else {
      printf("not ok %zd %s\n", i+1, test->name);
    }
  }
}

void tq_test_finish() {
  for (size_t i = 0; i < registered_tests_len; i++) {
    free(registered_tests[i].name);
  }

  free(registered_tests);
  registered_tests_cap = registered_tests_len = 0;
  registered_tests = NULL;
}

static void tq_test_finish_dtor(void) __attribute__((destructor));
static void tq_test_finish_dtor() {
  tq_test_finish();
}
