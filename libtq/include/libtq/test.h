#pragma once
#include <stdint.h>
#include <stdbool.h>
#include <libtq/macros.h>

/**
   @section Testing utilities

   This provides a simple mechanism to register tests and run them.
*/


/**
   The type of a test function.
 */
typedef bool (*tq_test_fn_t)(void);

/**
   Simple way to register a test with the testing system

   Example:

   ```
   TQ_TEST("foo/bar") {
     if (1 == 1) {
       return true;
     } else {
       return false;
     }
   }
   ```
     
*/
#define TQ_TEST(name)							\
  static bool TQ_PASTE(tq_usertest_fn_, __LINE__)(void);		\
  static void TQ_PASTE(tq_usertest_decl_, __LINE__)(void) __attribute__((constructor)); \
  static void TQ_PASTE(tq_usertest_decl_, __LINE__)() {			\
    tq_test_register(							\
		     TQ_PASTE(tq_usertest_fn_, __LINE__),		\
		     name);						\
  }									\
  static bool TQ_PASTE(tq_usertest_fn_, __LINE__)(void)

/**
   Register a test globally.
   
   This function makes a copy of the name. It is assumed that test
   setup is not going to be in a hot codepath, so we don't care much about performance
 */
void tq_test_register(tq_test_fn_t test_fn, const char* name);

/**
   Call after all testing is complete.

   This frees any memory used by the test framework. Unregisters all registered tests
 */
void tq_test_finish(void);

/**
   Run all registered tests
*/
void tq_test_run(void);
