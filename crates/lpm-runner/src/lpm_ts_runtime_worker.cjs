const childProcess = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");
const { workerData } = require("node:worker_threads");

const STATE_IDLE = 0;
const STATE_REQUEST = 1;
const STATE_RESPONSE = 2;
const CONTROL_STATE = 0;
const CONTROL_REQUEST_ID = 1;
const CONTROL_SHUTDOWN = 2;
const MAX_STDERR_BYTES = 64 * 1024;

const control = new Int32Array(workerData.sharedBuffer);
let helper = null;
let stdoutBuffer = "";
let stderrTail = "";
let pendingResolve = null;
let pendingReject = null;

run().catch((error) => {
  writeFatalResponse(error);
});

async function run() {
  while (Atomics.load(control, CONTROL_SHUTDOWN) === 0) {
    Atomics.wait(control, CONTROL_STATE, STATE_IDLE);
    if (Atomics.load(control, CONTROL_SHUTDOWN) !== 0) {
      break;
    }
    if (Atomics.load(control, CONTROL_STATE) !== STATE_REQUEST) {
      continue;
    }

    const requestId = Atomics.load(control, CONTROL_REQUEST_ID);
    await handleRequest(requestId);
    Atomics.store(control, CONTROL_STATE, STATE_RESPONSE);
    Atomics.notify(control, CONTROL_STATE, 1);

    while (
      Atomics.load(control, CONTROL_SHUTDOWN) === 0 &&
      Atomics.load(control, CONTROL_STATE) === STATE_RESPONSE
    ) {
      Atomics.wait(control, CONTROL_STATE, STATE_RESPONSE, 1000);
    }
  }

  stopHelper();
}

async function handleRequest(requestId) {
  const requestPath = path.join(workerData.sessionDir, `request-${requestId}.json`);
  const responsePath = path.join(workerData.sessionDir, `response-${requestId}.json`);
  try {
    const requestJson = fs.readFileSync(requestPath, "utf8");
    const responseJson = await transformWithHelper(requestJson);
    writeResponseFile(responsePath, responseJson);
  } catch (error) {
    writeResponseFile(responsePath, JSON.stringify(errorResponse(error)));
  }
}

function transformWithHelper(requestJson) {
  startHelper();
  return new Promise((resolve, reject) => {
    pendingResolve = resolve;
    pendingReject = reject;
    try {
      helper.stdin.write(`${requestJson}\n`, "utf8", (error) => {
        if (error) {
          rejectPending(error);
        }
      });
    } catch (error) {
      rejectPending(error);
    }
  });
}

function startHelper() {
  if (helper) {
    return;
  }

  stderrTail = "";
  stdoutBuffer = "";
  helper = childProcess.spawn(workerData.transformer, ["internal-ts-transform", "--persistent"], {
    stdio: ["pipe", "pipe", "pipe"],
    windowsHide: true,
  });
  helper.stdout.setEncoding("utf8");
  helper.stderr.setEncoding("utf8");
  helper.stdout.on("data", onStdout);
  helper.stderr.on("data", (chunk) => {
    stderrTail = `${stderrTail}${chunk}`.slice(-MAX_STDERR_BYTES);
  });
  helper.on("error", (error) => {
    const detail = new Error(`LPM OXC TypeScript helper failed to start: ${error.message}`);
    rejectPending(detail);
    helper = null;
  });
  helper.on("exit", (code, signal) => {
    const detail = helperExitError(code, signal);
    rejectPending(detail);
    helper = null;
  });
}

function onStdout(chunk) {
  stdoutBuffer += chunk;
  if (stdoutBuffer.length > workerData.maxTransformOutputBytes) {
    rejectPending(new Error("LPM OXC TypeScript helper response exceeded the output limit"));
    stopHelper();
    return;
  }
  drainStdout();
}

function drainStdout() {
  if (!pendingResolve) {
    return;
  }
  const lineEnd = stdoutBuffer.indexOf("\n");
  if (lineEnd === -1) {
    return;
  }

  let line = stdoutBuffer.slice(0, lineEnd);
  if (line.endsWith("\r")) {
    line = line.slice(0, -1);
  }
  stdoutBuffer = stdoutBuffer.slice(lineEnd + 1);
  const resolve = pendingResolve;
  pendingResolve = null;
  pendingReject = null;
  resolve(line);
}

function rejectPending(error) {
  if (!pendingReject) {
    return;
  }
  const reject = pendingReject;
  pendingResolve = null;
  pendingReject = null;
  reject(error);
}

function helperExitError(code, signal) {
  const status = signal ? `signal ${signal}` : `exit status ${code}`;
  const detail = stderrTail.trim();
  return new Error(detail ? `LPM OXC TypeScript helper exited with ${status}:\n${detail}` : `LPM OXC TypeScript helper exited with ${status}`);
}

function writeResponseFile(responsePath, responseJson) {
  const tmpPath = `${responsePath}.${process.pid}.tmp`;
  fs.writeFileSync(tmpPath, responseJson, { encoding: "utf8", mode: 0o600 });
  fs.renameSync(tmpPath, responsePath);
}

function errorResponse(error) {
  return {
    schemaVersion: workerData.protocolVersion,
    transportError: true,
    error: error && error.message ? error.message : String(error),
  };
}

function writeFatalResponse(error) {
  const requestId = Atomics.load(control, CONTROL_REQUEST_ID);
  if (requestId > 0) {
    const responsePath = path.join(workerData.sessionDir, `response-${requestId}.json`);
    try {
      writeResponseFile(responsePath, JSON.stringify(errorResponse(error)));
    } catch (_writeError) {
      // The parent will time out if the response path cannot be written.
    }
  }
  Atomics.store(control, CONTROL_STATE, STATE_RESPONSE);
  Atomics.notify(control, CONTROL_STATE, 1);
  stopHelper();
}

function stopHelper() {
  if (!helper) {
    return;
  }
  const child = helper;
  helper = null;
  child.kill();
}
