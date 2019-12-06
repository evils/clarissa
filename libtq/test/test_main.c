#include <libtq/test.h>

int main(int argc, char** argv) {
  (void)argc;
  (void)argv;

  tq_test_run();
  tq_test_finish();
}
