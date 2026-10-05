/** Native log records delivered to the host every `LOG_MS`, at most `LOG_RECORDS` per delivery. */
export const LOG_MS = 250;
export const LOG_RECORDS = 32;
/** Deliveries of the final drain once native closed. */
const LOG_FINAL = 4;
/** Record loss is reported at most this often, with every loss since the last report. */
const LOG_LOSS_MS = 30000;
export const LOG_ERRORS_NAME = "lodestar_native_log_delivery_errors_total";
export const LOG_DRAIN_ERRORS_NAME = "lodestar_native_log_drain_errors_total";

/** Delivers bounded log batches; its timer holds it weakly so it cannot retain a dropped facade. */
export class LogDelivery {
  #runtime;
  #host;
  #onError;
  #weak = new WeakRef(this);
  #stopped = false;
  #logTimer = undefined;
  #logErrors = 0;
  #drainErrors = 0;
  #logLoss = {at: Number.NEGATIVE_INFINITY, dropped: 0n, suppressed: 0n, truncated: 0n};

  constructor(runtime, host, onError) {
    this.#runtime = runtime;
    this.#host = host;
    this.#onError = onError;
  }

  stop() {
    this.#stopped = true;
    if (this.#logTimer) clearTimeout(this.#logTimer);
    this.#logTimer = undefined;
    this.#deliverLogs(LOG_FINAL);
  }

  start() {
    this.#logTimer = setTimeout(LogDelivery.#logFired, LOG_MS, this.#weak).unref();
  }

  static #logFired(weak) {
    const logs = weak.deref();
    if (!logs || logs.#stopped) return;
    logs.#deliverLogs(1);
    logs.start();
  }

  /**
   * Hands up to `deliveries` batches of native log records to the host, with the record loss since the last report
   * when it grew. Records a throwing handler did not take count as delivery errors; delivery never fails the network.
   */
  #deliverLogs(deliveries) {
    for (let i = 0; i < deliveries; i++) {
      let batch;
      try {
        batch = this.#runtime.drainLogs(LOG_RECORDS);
      } catch (error) {
        this.#drainErrors++;
        this.#onError(error);
        return;
      }
      const loss = this.#lostLogs(batch);
      if (batch.records.length > 0 || loss !== null) {
        try {
          this.#host.logs(batch.records, loss);
          if (loss !== null) {
            this.#logLoss = {
              at: performance.now(),
              dropped: batch.dropped,
              suppressed: batch.suppressed,
              truncated: batch.truncated,
            };
          }
        } catch {
          this.#logErrors += batch.records.length;
        }
      }
      if (!batch.more) return;
    }
  }

  /** Record loss since the last report, at most every `LOG_LOSS_MS` while running. */
  #lostLogs(batch) {
    const reported = this.#logLoss;
    if (
      batch.dropped === reported.dropped &&
      batch.suppressed === reported.suppressed &&
      batch.truncated === reported.truncated
    )
      return null;
    const now = performance.now();
    if (!this.#stopped && now - reported.at < LOG_LOSS_MS) return null;
    return {
      dropped: batch.dropped - reported.dropped,
      suppressed: batch.suppressed - reported.suppressed,
      truncated: batch.truncated - reported.truncated,
    };
  }

  metrics() {
    return [
      `# HELP ${LOG_ERRORS_NAME} Native log records that left the native queue but did not reach the host's log handler`,
      `# TYPE ${LOG_ERRORS_NAME} counter`,
      `${LOG_ERRORS_NAME} ${this.#logErrors}`,
      `# HELP ${LOG_DRAIN_ERRORS_NAME} Failed attempts to drain native log records`,
      `# TYPE ${LOG_DRAIN_ERRORS_NAME} counter`,
      `${LOG_DRAIN_ERRORS_NAME} ${this.#drainErrors}`,
      "",
    ].join("\n");
  }
}
