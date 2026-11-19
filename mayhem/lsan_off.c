/* Leak detection off at build time (leaks are not the bug class fuzzed here). */
int __lsan_is_turned_off (void) { return 1; }
