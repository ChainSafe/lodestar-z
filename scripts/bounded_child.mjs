import {spawn} from "node:child_process";

const OUTPUT_DRAIN_TIMEOUT_MS = 1000;

function commandError(code, detail = "") {
  const error = new Error(detail === "" ? code : `${code}: ${detail}`);
  error.code = code;
  return error;
}

function terminate(child) {
  if (child.pid === undefined) return;
  try {
    process.kill(-child.pid, "SIGKILL");
  } catch {
    if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
  }
}

function capture(reader, name, state, child) {
  return new Promise((resolve, reject) => {
    reader.on("data", (chunk) => {
      state.bytes += chunk.length;
      if (state.bytes > state.maxOutputBytes) {
        const remaining = state.maxOutputBytes - state.storedBytes;
        if (remaining > 0) {
          state[name].push(chunk.subarray(0, remaining));
          state.storedBytes += remaining;
        }
        state.error ??= commandError("CommandOutputBound", `combined output exceeds ${state.maxOutputBytes} bytes`);
        terminate(child);
        return;
      }
      state[name].push(chunk);
      state.storedBytes += chunk.length;
    });
    reader.once("end", resolve);
    reader.once("error", reject);
  });
}

async function boundedDrain(promises, readers) {
  let timer;
  try {
    await Promise.race([
      Promise.all(promises),
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(commandError("CommandOutputDrainTimeout")), OUTPUT_DRAIN_TIMEOUT_MS);
      }),
    ]);
  } finally {
    clearTimeout(timer);
    for (const reader of readers) reader.destroy();
  }
}

export async function runBoundedCommand(
  program,
  args,
  cwd,
  {allowFailure = false, env = process.env, maxOutputBytes, timeoutMs}
) {
  if (!Array.isArray(args) || args.some((arg) => typeof arg !== "string")) throw new Error("InvalidCommand");
  if (!Number.isSafeInteger(maxOutputBytes) || maxOutputBytes <= 0) throw new Error("InvalidOutputBound");
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0) throw new Error("InvalidCommandTimeout");
  let child;
  try {
    const startedAt = new Date().toISOString();
    child = spawn(program, args, {
      cwd,
      detached: true,
      env,
      stdio: ["ignore", "pipe", "pipe"],
    });
    const state = {bytes: 0, error: undefined, maxOutputBytes, stderr: [], stdout: [], storedBytes: 0};
    const captures = [
      capture(child.stdout, "stdout", state, child).catch((error) => {
        error.code ??= "CommandOutputReadFailed";
        state.error ??= error;
        terminate(child);
      }),
      capture(child.stderr, "stderr", state, child).catch((error) => {
        error.code ??= "CommandOutputReadFailed";
        state.error ??= error;
        terminate(child);
      }),
    ];
    const timer = setTimeout(() => {
      state.error ??= commandError("CommandTimeout", `exceeded ${timeoutMs}ms`);
      terminate(child);
    }, timeoutMs);
    const result = await new Promise((resolveResult) => {
      child.once("error", (error) => resolveResult({exitCode: null, signal: null, spawnError: error}));
      // Descendants can retain the pipes after the leader exits; the bounded drain owns that wait.
      child.once("exit", (exitCode, signal) => resolveResult({exitCode, signal}));
    });
    let drainError;
    try {
      await boundedDrain(captures, [child.stdout, child.stderr]);
    } catch (error) {
      drainError = error;
    } finally {
      clearTimeout(timer);
    }
    const record = {
      argv: [program, ...args],
      cwd,
      exitCode: result.exitCode,
      finishedAt: new Date().toISOString(),
      signal: result.signal,
      startedAt,
      stderr: Buffer.concat(state.stderr).toString("utf8"),
      stdout: Buffer.concat(state.stdout).toString("utf8"),
    };
    if (state.error || drainError) {
      const error = state.error ?? drainError;
      error.commandRecord = record;
      throw error;
    }
    if (result.spawnError) {
      result.spawnError.commandRecord = record;
      throw result.spawnError;
    }
    if (!allowFailure && result.exitCode !== 0) {
      const error = commandError("CommandFailed", `exit code ${record.exitCode}`);
      error.commandRecord = record;
      throw error;
    }
    return record;
  } finally {
    if (child !== undefined) terminate(child);
    child?.stdout?.destroy();
    child?.stderr?.destroy();
  }
}
