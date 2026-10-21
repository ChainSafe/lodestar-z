// Deterministic process clock for fuzz harnesses, loaded with LD_PRELOAD (AFL_PRELOAD under
// afl-fuzz). It replaces the libc clock reads that quiche's timers depend on with a counter
// held in this process's own memory: it starts at a fixed instant, moves only when the harness
// calls fuzz_clock_advance (or by FUZZ_CLOCK_STEP_NS per read when that is set), and a fork
// child inherits the parent's value by copy, so every snapshot child starts at the same time
// and advances independently of its siblings.
#define _GNU_SOURCE
#include <stdint.h>
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>

// 2026-01-01T00:00:00Z for the realtime clocks; the monotonic clocks start at one second so
// callers that subtract an epoch never see zero.
static const int64_t realtime_base_ns = 1767225600LL * 1000000000LL;
static const int64_t monotonic_base_ns = 1000000000LL;
static int64_t elapsed_ns = 0;
static int64_t step_ns = -1;

static int64_t read_clock(clockid_t id) {
  if (step_ns < 0) {
    const char* step = getenv("FUZZ_CLOCK_STEP_NS");
    step_ns = step ? atoll(step) : 0;
    if (step_ns < 0) step_ns = 0;
  }
  elapsed_ns += step_ns;
  switch (id) {
    case CLOCK_REALTIME:
    case CLOCK_REALTIME_COARSE:
      return realtime_base_ns + elapsed_ns;
    default:
      return monotonic_base_ns + elapsed_ns;
  }
}

void fuzz_clock_advance(int64_t ns) {
  if (ns > 0) elapsed_ns += ns;
}

int clock_gettime(clockid_t id, struct timespec* ts) {
  const int64_t now = read_clock(id);
  ts->tv_sec = now / 1000000000LL;
  ts->tv_nsec = now % 1000000000LL;
  return 0;
}

int gettimeofday(struct timeval* tv, void* tz) {
  (void)tz;
  const int64_t now = read_clock(CLOCK_REALTIME);
  tv->tv_sec = now / 1000000000LL;
  tv->tv_usec = (now % 1000000000LL) / 1000;
  return 0;
}

time_t time(time_t* out) {
  const time_t now = read_clock(CLOCK_REALTIME) / 1000000000LL;
  if (out) *out = now;
  return now;
}
