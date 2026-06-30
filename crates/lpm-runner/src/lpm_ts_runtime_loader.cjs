const childProcess = require("node:child_process");
const crypto = require("node:crypto");
const fs = require("node:fs");
const moduleApi = require("node:module");
const path = require("node:path");
const { pathToFileURL, fileURLToPath } = require("node:url");
const { Worker } = require("node:worker_threads");

const RUNTIME_VERSION = "5";
const TRANSFORM_PROTOCOL_VERSION = 1;
const CACHE_ENTRY_SCHEMA_VERSION = 1;
const TS_EXT_RE = /\.(?:ts|tsx|mts|cts)$/;
const JS_EXTS = [".ts", ".tsx", ".mts", ".cts", ".js", ".mjs", ".cjs", ".json"];
const PROJECT_DIR = path.resolve(process.env.LPM_TS_RUNTIME_PROJECT_DIR || process.cwd());
const CACHE_DIR =
  process.env.LPM_TS_RUNTIME_CACHE_DIR ||
  path.join(PROJECT_DIR, ".lpm", "exec-ts-runtime-cache");
const TRANSFORMER = process.env.LPM_TS_RUNTIME_TRANSFORMER;
const WORKER_PATH = path.join(__dirname, "lpm-ts-runtime-worker.cjs");
const TRACE_ENABLED = process.env.LPM_TS_RUNTIME_TRACE === "1";
let TRACE_FILE = TRACE_ENABLED ? process.env.LPM_TS_RUNTIME_TRACE_FILE : "";
const MAX_TRANSFORM_OUTPUT_BYTES = 64 * 1024 * 1024;
const PERSISTENT_TRANSFORM_TIMEOUT_MS = 120 * 1000;
const INLINE_REQUEST_BUFFER_BYTES = 256 * 1024;
const INLINE_RESPONSE_BUFFER_BYTES = 4 * 1024 * 1024;
const STATE_IDLE = 0;
const STATE_REQUEST = 1;
const STATE_RESPONSE = 2;
const MODE_NONE = 0;
const MODE_INLINE = 1;
const MODE_FILE = 2;
const CONTROL_STATE = 0;
const CONTROL_REQUEST_ID = 1;
const CONTROL_SHUTDOWN = 2;
const CONTROL_REQUEST_MODE = 3;
const CONTROL_REQUEST_BYTES = 4;
const CONTROL_RESPONSE_MODE = 5;
const CONTROL_RESPONSE_BYTES = 6;

let persistentTransformClient = null;
let persistentTransformUnavailable = false;
let traceFd = null;

if (typeof moduleApi.registerHooks !== "function") {
  throw new Error("LPM TS runtime requires Node.js module.registerHooks support. Run `lpm use node@22.18+`.");
}

if (!TRANSFORMER) {
  throw new Error("LPM TS runtime could not find its OXC transformer helper. Run this file through `lpm exec`.");
}

if (
  process.env.LPM_TS_RUNTIME_PROTOCOL_VERSION &&
  Number(process.env.LPM_TS_RUNTIME_PROTOCOL_VERSION) !== TRANSFORM_PROTOCOL_VERSION
) {
  throw new Error("LPM TS runtime helper protocol mismatch. Re-run `lpm exec` so LPM can refresh the runtime.");
}

const tsconfig = loadTsconfig(PROJECT_DIR);
const compilerOptions = tsconfig.compilerOptions || {};
const tsconfigFingerprint = hashJson(compilerOptions);

moduleApi.registerHooks({
  resolve(specifier, context, nextResolve) {
    const traceStart = TRACE_ENABLED ? process.hrtime.bigint() : 0n;
    const mapped = resolveSpecifier(specifier, context.parentURL);
    if (TRACE_ENABLED) {
      traceEvent("resolve", traceStart, {
        specifier,
        parentURL: context.parentURL || "",
        result: mapped ? mapped.fileUrl || mapped : "next",
      });
    }
    if (mapped) {
      return { url: mapped.fileUrl || pathToFileURL(mapped).href, shortCircuit: true };
    }
    return nextResolve(specifier, context);
  },
  load(url, context, nextLoad) {
    if (!url.startsWith("file:")) {
      return nextLoad(url, context);
    }

    const filename = fileURLToPath(url);
    if (!TS_EXT_RE.test(filename)) {
      return nextLoad(url, context);
    }

    const loadStart = TRACE_ENABLED ? process.hrtime.bigint() : 0n;
    const readStart = TRACE_ENABLED ? process.hrtime.bigint() : 0n;
    const source = fs.readFileSync(filename, "utf8");
    if (TRACE_ENABLED) {
      traceEvent("source_read", readStart, { filename, bytes: Buffer.byteLength(source) });
    }
    const formatStart = TRACE_ENABLED ? process.hrtime.bigint() : 0n;
    const format = moduleFormat(filename, source);
    if (TRACE_ENABLED) {
      traceEvent("module_format", formatStart, { filename, format });
    }
    const transformedSource = loadTransformedSource(filename, source, format);
    if (TRACE_ENABLED) {
      traceEvent("load_hook", loadStart, { filename, format });
    }
    return {
      format,
      source: transformedSource,
      shortCircuit: true,
    };
  },
});

function loadTransformedSource(filename, source, format) {
  const options = transformOptionsFor(format);
  const cacheKeyStart = TRACE_ENABLED ? process.hrtime.bigint() : 0n;
  const key = cacheKey(filename, source, format, options);
  if (TRACE_ENABLED) {
    traceEvent("cache_key", cacheKeyStart, { filename, format, key });
  }
  const cachePath = path.join(CACHE_DIR, `${key}.json`);
  const cacheLookupStart = TRACE_ENABLED ? process.hrtime.bigint() : 0n;
  const cached = readCacheEntry(cachePath, key);
  if (TRACE_ENABLED) {
    traceEvent("cache_lookup", cacheLookupStart, {
      filename,
      cachePath,
      hit: cached !== null,
    });
  }
  if (cached) {
    return cached;
  }

  const transformStart = TRACE_ENABLED ? process.hrtime.bigint() : 0n;
  const transformed = transformSource(filename, source, format, options);
  if (TRACE_ENABLED) {
    traceEvent("transform_roundtrip", transformStart, {
      filename,
      format,
      bytesIn: Buffer.byteLength(source),
      bytesOut: Buffer.byteLength(transformed),
    });
  }
  const cacheWriteStart = TRACE_ENABLED ? process.hrtime.bigint() : 0n;
  fs.mkdirSync(CACHE_DIR, { recursive: true });
  const tmp = `${cachePath}.${process.pid}.tmp`;
  const envelope = {
    schemaVersion: CACHE_ENTRY_SCHEMA_VERSION,
    cacheKey: key,
    runtimeVersion: RUNTIME_VERSION,
    protocolVersion: TRANSFORM_PROTOCOL_VERSION,
    filename,
    code: transformed,
  };
  fs.writeFileSync(tmp, JSON.stringify(envelope));
  fs.renameSync(tmp, cachePath);
  if (TRACE_ENABLED) {
    traceEvent("cache_write", cacheWriteStart, {
      filename,
      cachePath,
      bytes: Buffer.byteLength(transformed),
    });
  }
  return transformed;
}

function readCacheEntry(cachePath, expectedKey) {
  let raw;
  try {
    raw = fs.readFileSync(cachePath, "utf8");
  } catch (error) {
    if (error && error.code === "ENOENT") {
      return null;
    }
    throw error;
  }

  let entry;
  try {
    entry = JSON.parse(raw);
  } catch (_error) {
    return null;
  }

  if (
    entry &&
    entry.schemaVersion === CACHE_ENTRY_SCHEMA_VERSION &&
    entry.cacheKey === expectedKey &&
    entry.runtimeVersion === RUNTIME_VERSION &&
    entry.protocolVersion === TRANSFORM_PROTOCOL_VERSION &&
    typeof entry.code === "string"
  ) {
    return entry.code;
  }
  return null;
}

function transformSource(filename, source, format, options) {
  const request = {
    schemaVersion: TRANSFORM_PROTOCOL_VERSION,
    filename,
    source,
    format,
    sourceMap: true,
    options,
  };

  if (!persistentTransformUnavailable) {
    try {
      const persistentResult = transformSourceWithPersistentHelper(request, filename);
      if (persistentResult !== null) {
        return persistentResult;
      }
    } catch (error) {
      if (!error || !error.lpmPersistentTransport) {
        throw error;
      }
      persistentTransformUnavailable = true;
      shutdownPersistentTransformClient();
    }
  }

  return transformSourceOnce(request, filename);
}

function transformSourceOnce(request, filename) {
  const result = childProcess.spawnSync(TRANSFORMER, ["internal-ts-transform"], {
    input: JSON.stringify(request),
    encoding: "utf8",
    maxBuffer: MAX_TRANSFORM_OUTPUT_BYTES,
    windowsHide: true,
  });

  if (result.error) {
    throw new Error(`LPM OXC TypeScript transform failed to start: ${result.error.message}`);
  }
  if (result.status !== 0) {
    const stderr = String(result.stderr || "").trim();
    const stdout = String(result.stdout || "").trim();
    const detail = stderr || stdout || `exit status ${result.status}`;
    throw new Error(`LPM OXC TypeScript transform failed for ${filename}:\n${detail}`);
  }

  let response;
  try {
    response = JSON.parse(result.stdout);
  } catch (error) {
    throw new Error(`LPM OXC TypeScript transform returned invalid JSON for ${filename}: ${error.message}`);
  }
  if (
    !response ||
    response.schemaVersion !== TRANSFORM_PROTOCOL_VERSION ||
    typeof response.code !== "string"
  ) {
    throw new Error(`LPM OXC TypeScript transform returned an invalid response for ${filename}`);
  }
  return response.code;
}

function transformSourceWithPersistentHelper(request, filename) {
  const client = ensurePersistentTransformClient();
  if (!client) {
    return null;
  }

  const requestId = ++client.nextRequestId;
  const requestPath = path.join(client.sessionDir, `request-${requestId}.json`);
  const responsePath = path.join(client.sessionDir, `response-${requestId}.json`);
  const requestTmpPath = `${requestPath}.${process.pid}.tmp`;
  const requestJson = JSON.stringify(request);
  const requestPayload = Buffer.from(requestJson);
  const requestMode = requestPayload.length <= client.requestBuffer.byteLength ? MODE_INLINE : MODE_FILE;
  let resetToIdle = false;
  const transportStart = TRACE_ENABLED ? process.hrtime.bigint() : 0n;
  let responseMode = MODE_NONE;
  let responseBytes = 0;

  try {
    if (Atomics.load(client.control, CONTROL_STATE) !== STATE_IDLE) {
      throw persistentTransportError("LPM TS runtime persistent helper is not idle");
    }

    Atomics.store(client.control, CONTROL_RESPONSE_MODE, MODE_NONE);
    Atomics.store(client.control, CONTROL_RESPONSE_BYTES, 0);
    if (requestMode === MODE_INLINE) {
      client.requestBytes.set(requestPayload);
    } else {
      fs.writeFileSync(requestTmpPath, requestJson, { encoding: "utf8", mode: 0o600 });
      fs.renameSync(requestTmpPath, requestPath);
    }

    Atomics.store(client.control, CONTROL_REQUEST_ID, requestId);
    Atomics.store(client.control, CONTROL_REQUEST_MODE, requestMode);
    Atomics.store(client.control, CONTROL_REQUEST_BYTES, requestPayload.length);
    Atomics.store(client.control, CONTROL_STATE, STATE_REQUEST);
    Atomics.notify(client.control, CONTROL_STATE, 1);

    waitForPersistentResponse(client, filename);
    resetToIdle = true;

    responseMode = Atomics.load(client.control, CONTROL_RESPONSE_MODE);
    responseBytes = Atomics.load(client.control, CONTROL_RESPONSE_BYTES);
    let response;
    try {
      response = JSON.parse(readPersistentResponse(client, responsePath, responseMode, responseBytes));
    } catch (error) {
      throw persistentTransportError(`LPM OXC TypeScript transform returned invalid JSON for ${filename}: ${error.message}`);
    }

    if (!response || response.schemaVersion !== TRANSFORM_PROTOCOL_VERSION) {
      throw persistentTransportError(`LPM OXC TypeScript transform returned an invalid response for ${filename}`);
    }
    if (response.transportError && typeof response.error === "string") {
      throw persistentTransportError(`LPM OXC TypeScript persistent helper failed for ${filename}:\n${response.error}`);
    }
    if (typeof response.error === "string") {
      throw new Error(`LPM OXC TypeScript transform failed for ${filename}:\n${response.error}`);
    }
    if (typeof response.code !== "string") {
      throw persistentTransportError(`LPM OXC TypeScript transform returned an invalid response for ${filename}`);
    }
    if (TRACE_ENABLED) {
      traceEvent("persistent_transport", transportStart, {
        filename,
        requestMode: modeName(requestMode),
        responseMode: modeName(responseMode),
        requestBytes: requestPayload.length,
        responseBytes,
      });
    }
    return response.code;
  } finally {
    try {
      fs.rmSync(requestTmpPath, { force: true });
      if (requestMode === MODE_FILE) {
        fs.rmSync(requestPath, { force: true });
      }
      if (responseMode === MODE_FILE) {
        fs.rmSync(responsePath, { force: true });
      }
    } catch (_error) {
      // Best-effort cleanup for short-lived IPC files.
    }
    if (resetToIdle) {
      Atomics.store(client.control, CONTROL_STATE, STATE_IDLE);
      Atomics.notify(client.control, CONTROL_STATE, 1);
    }
  }
}

function readPersistentResponse(client, responsePath, responseMode, responseBytes) {
  if (responseMode === MODE_INLINE) {
    return Buffer.from(client.responseBytes.subarray(0, responseBytes)).toString("utf8");
  }
  if (responseMode === MODE_FILE) {
    return fs.readFileSync(responsePath, "utf8");
  }
  throw persistentTransportError("LPM OXC TypeScript persistent helper did not publish a response");
}

function ensurePersistentTransformClient() {
  if (persistentTransformUnavailable || process.env.LPM_TS_RUNTIME_PERSISTENT_TRANSFORM === "0") {
    return null;
  }
  if (persistentTransformClient) {
    return persistentTransformClient;
  }
  if (
    typeof Worker !== "function" ||
    typeof SharedArrayBuffer !== "function" ||
    typeof Atomics.wait !== "function" ||
    !fs.existsSync(WORKER_PATH)
  ) {
    persistentTransformUnavailable = true;
    return null;
  }

  const sessionRoot = path.join(CACHE_DIR, "sessions");
  const sessionDir = path.join(
    sessionRoot,
    `${process.pid}-${Date.now()}-${crypto.randomBytes(4).toString("hex")}`
  );
  fs.mkdirSync(sessionDir, { recursive: true });

  const sharedBuffer = new SharedArrayBuffer(7 * Int32Array.BYTES_PER_ELEMENT);
  const requestBuffer = new SharedArrayBuffer(INLINE_REQUEST_BUFFER_BYTES);
  const responseBuffer = new SharedArrayBuffer(INLINE_RESPONSE_BUFFER_BYTES);
  const control = new Int32Array(sharedBuffer);
  const client = {
    control,
    nextRequestId: 0,
    requestBuffer,
    requestBytes: new Uint8Array(requestBuffer),
    responseBuffer,
    responseBytes: new Uint8Array(responseBuffer),
    sessionDir,
    worker: null,
  };

  try {
    client.worker = new Worker(WORKER_PATH, {
      execArgv: [],
      env: persistentWorkerEnv(),
      workerData: {
        sessionDir,
        sharedBuffer,
        requestBuffer,
        responseBuffer,
        transformer: TRANSFORMER,
        protocolVersion: TRANSFORM_PROTOCOL_VERSION,
        maxTransformOutputBytes: MAX_TRANSFORM_OUTPUT_BYTES,
      },
    });
  } catch (_error) {
    persistentTransformUnavailable = true;
    cleanupPersistentSession(sessionDir);
    return null;
  }

  client.worker.unref();
  client.worker.on("error", () => {
    persistentTransformUnavailable = true;
  });
  client.worker.on("exit", (code) => {
    if (code !== 0) {
      persistentTransformUnavailable = true;
    }
  });
  process.once("exit", shutdownPersistentTransformClient);
  persistentTransformClient = client;
  return client;
}

function persistentWorkerEnv() {
  const env = { ...process.env };
  delete env.NODE_OPTIONS;
  return env;
}

function modeName(mode) {
  if (mode === MODE_INLINE) {
    return "inline";
  }
  if (mode === MODE_FILE) {
    return "file";
  }
  return "none";
}

function waitForPersistentResponse(client, filename) {
  const deadline = Date.now() + PERSISTENT_TRANSFORM_TIMEOUT_MS;
  while (Atomics.load(client.control, CONTROL_STATE) === STATE_REQUEST) {
    const remaining = deadline - Date.now();
    if (remaining <= 0) {
      Atomics.store(client.control, CONTROL_SHUTDOWN, 1);
      Atomics.notify(client.control, CONTROL_STATE, 1);
      throw persistentTransportError(`LPM OXC TypeScript persistent helper timed out for ${filename}`);
    }
    Atomics.wait(client.control, CONTROL_STATE, STATE_REQUEST, Math.min(remaining, 1000));
  }

  if (Atomics.load(client.control, CONTROL_STATE) !== STATE_RESPONSE) {
    throw persistentTransportError(`LPM OXC TypeScript persistent helper stopped before transforming ${filename}`);
  }
}

function persistentTransportError(message) {
  const error = new Error(message);
  error.lpmPersistentTransport = true;
  return error;
}

function shutdownPersistentTransformClient() {
  const client = persistentTransformClient;
  if (!client) {
    return;
  }
  persistentTransformClient = null;
  Atomics.store(client.control, CONTROL_SHUTDOWN, 1);
  Atomics.notify(client.control, CONTROL_STATE, 1);
  try {
    client.worker.terminate();
  } catch (_error) {
    persistentTransformUnavailable = true;
  }
  cleanupPersistentSession(client.sessionDir);
}

function cleanupPersistentSession(sessionDir) {
  try {
    fs.rmSync(sessionDir, { recursive: true, force: true });
  } catch (_error) {
    persistentTransformUnavailable = true;
  }
}

function transformOptionsFor(format) {
  const jsx = {
    runtime: "automatic",
    development: compilerOptions.jsx === "react-jsxdev",
  };
  if (compilerOptions.jsx === "react" || compilerOptions.jsxFactory || compilerOptions.jsxFragmentFactory) {
    jsx.runtime = "classic";
  }
  if (typeof compilerOptions.jsxImportSource === "string") {
    jsx.importSource = compilerOptions.jsxImportSource;
  }
  if (typeof compilerOptions.jsxFactory === "string") {
    jsx.pragma = compilerOptions.jsxFactory;
  }
  if (typeof compilerOptions.jsxFragmentFactory === "string") {
    jsx.pragmaFrag = compilerOptions.jsxFragmentFactory;
  }
  return {
    format,
    jsx,
  };
}

function cacheKey(filename, source, format, options) {
  return hashJson({
    runtimeVersion: RUNTIME_VERSION,
    protocolVersion: TRANSFORM_PROTOCOL_VERSION,
    nodeVersion: process.versions.node,
    platform: process.platform,
    arch: process.arch,
    filename,
    tsconfigFingerprint,
    format,
    options,
    sourceHash: hashString(source),
  });
}

function hashString(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function hashJson(value) {
  return hashString(JSON.stringify(value || {}));
}

function loadTsconfig(projectDir) {
  const tsconfigPath = path.join(projectDir, "tsconfig.json");
  const traceStart = TRACE_ENABLED ? process.hrtime.bigint() : 0n;
  try {
    const text = fs.readFileSync(tsconfigPath, "utf8");
    const parsed = JSON.parse(stripJsonComments(text));
    if (TRACE_ENABLED) {
      traceEvent("tsconfig_load", traceStart, { tsconfigPath, found: true });
    }
    return parsed;
  } catch (_error) {
    if (TRACE_ENABLED) {
      traceEvent("tsconfig_load", traceStart, { tsconfigPath, found: false });
    }
    return {};
  }
}

function stripJsonComments(text) {
  return text
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/(^|[^:])\/\/.*$/gm, "$1");
}

function moduleFormat(filename, source) {
  if (filename.endsWith(".mts")) {
    return "module";
  }
  if (filename.endsWith(".cts")) {
    return "commonjs";
  }
  const packageType = nearestPackageType(filename);
  if (packageType === "module") {
    return "module";
  }
  return hasEsmSyntax(source) ? "module" : "commonjs";
}

function nearestPackageType(filename) {
  let current = path.dirname(filename);
  while (true) {
    const packageJson = path.join(current, "package.json");
    try {
      const parsed = JSON.parse(fs.readFileSync(packageJson, "utf8"));
      return parsed && parsed.type === "module" ? "module" : "commonjs";
    } catch (_error) {
      const parent = path.dirname(current);
      if (parent === current) {
        return "commonjs";
      }
      current = parent;
    }
  }
}

function hasEsmSyntax(source) {
  const masked = sourceSyntaxMask(source);
  return (
    hasImportMetaSyntax(masked) ||
    hasTopLevelAwaitSyntax(masked) ||
    hasRuntimeImportSyntax(masked) ||
    hasRuntimeExportSyntax(masked)
  );
}

function hasImportMetaSyntax(source) {
  let index = 0;
  while ((index = findWord(source, "import", index)) !== -1) {
    let cursor = skipWhitespace(source, index + "import".length);
    if (source[cursor] === ".") {
      cursor = skipWhitespace(source, cursor + 1);
      if (startsWordAt(source, cursor, "meta")) {
        return true;
      }
    }
    index += "import".length;
  }
  return false;
}

function hasTopLevelAwaitSyntax(source) {
  let curlyDepth = 0;
  for (let index = 0; index < source.length; index += 1) {
    const ch = source[index];
    if (ch === "{") {
      curlyDepth += 1;
      continue;
    }
    if (ch === "}") {
      curlyDepth = Math.max(0, curlyDepth - 1);
      continue;
    }
    if (curlyDepth === 0 && startsWordAt(source, index, "await")) {
      return true;
    }
  }
  return false;
}

function hasRuntimeImportSyntax(source) {
  let index = 0;
  while ((index = findWord(source, "import", index)) !== -1) {
    let cursor = skipWhitespace(source, index + "import".length);
    const ch = source[cursor];
    if (ch === "(" || ch === ".") {
      index += "import".length;
      continue;
    }
    if (startsWordAt(source, cursor, "type")) {
      index += "import".length;
      continue;
    }
    const importEquals = readIdentifier(source, cursor);
    if (importEquals) {
      const afterIdentifier = skipWhitespace(source, importEquals.end);
      if (source[afterIdentifier] === "=") {
        index += "import".length;
        continue;
      }
    }
    if (ch === "{") {
      const end = matchingBraceEnd(source, cursor);
      if (end !== -1 && allTypeSpecifiers(source.slice(cursor + 1, end))) {
        index = end + 1;
        continue;
      }
    }
    return true;
  }
  return false;
}

function hasRuntimeExportSyntax(source) {
  let index = 0;
  while ((index = findWord(source, "export", index)) !== -1) {
    let cursor = skipWhitespace(source, index + "export".length);
    if (
      startsWordAt(source, cursor, "type") ||
      startsWordAt(source, cursor, "interface") ||
      startsWordAt(source, cursor, "declare")
    ) {
      index += "export".length;
      continue;
    }
    if (source[cursor] === "=") {
      index += "export".length;
      continue;
    }
    if (source[cursor] === "{") {
      const end = matchingBraceEnd(source, cursor);
      if (end !== -1 && allTypeSpecifiers(source.slice(cursor + 1, end))) {
        index = end + 1;
        continue;
      }
    }
    return true;
  }
  return false;
}

function findWord(source, word, start) {
  let index = start;
  while ((index = source.indexOf(word, index)) !== -1) {
    if (startsWordAt(source, index, word)) {
      return index;
    }
    index += word.length;
  }
  return -1;
}

function startsWordAt(source, index, word) {
  return (
    source.startsWith(word, index) &&
    !isIdentifierChar(source[index - 1] || "") &&
    !isIdentifierChar(source[index + word.length] || "")
  );
}

function readIdentifier(source, index) {
  if (!/[A-Za-z_$]/.test(source[index] || "")) {
    return null;
  }
  let end = index + 1;
  while (/[A-Za-z0-9_$]/.test(source[end] || "")) {
    end += 1;
  }
  return { value: source.slice(index, end), end };
}

function skipWhitespace(source, index) {
  let cursor = index;
  while (cursor < source.length && /\s/.test(source[cursor])) {
    cursor += 1;
  }
  return cursor;
}

function matchingBraceEnd(source, start) {
  let depth = 0;
  for (let index = start; index < source.length; index += 1) {
    if (source[index] === "{") {
      depth += 1;
    } else if (source[index] === "}") {
      depth -= 1;
      if (depth === 0) {
        return index;
      }
    }
  }
  return -1;
}

function allTypeSpecifiers(specifiers) {
  const parts = specifiers
    .split(",")
    .map((part) => part.trim())
    .filter(Boolean);
  return parts.length > 0 && parts.every((part) => part === "type" || part.startsWith("type "));
}

function sourceSyntaxMask(source) {
  let out = "";
  let index = 0;
  while (index < source.length) {
    const ch = source[index];
    const next = source[index + 1];
    if (ch === "/" && next === "/") {
      out += "  ";
      index += 2;
      while (index < source.length && source[index] !== "\n" && source[index] !== "\r") {
        out += " ";
        index += 1;
      }
      continue;
    }
    if (ch === "/" && next === "*") {
      out += "  ";
      index += 2;
      while (index < source.length) {
        if (source[index] === "*" && source[index + 1] === "/") {
          out += "  ";
          index += 2;
          break;
        }
        out += source[index] === "\n" || source[index] === "\r" ? source[index] : " ";
        index += 1;
      }
      continue;
    }
    if (ch === "\"" || ch === "'" || ch === "`") {
      const quote = ch;
      out += " ";
      index += 1;
      while (index < source.length) {
        const current = source[index];
        out += current === "\n" || current === "\r" ? current : " ";
        index += 1;
        if (current === "\\") {
          if (index < source.length) {
            out += source[index] === "\n" || source[index] === "\r" ? source[index] : " ";
            index += 1;
          }
          continue;
        }
        if (current === quote) {
          break;
        }
      }
      continue;
    }
    if (ch === "/" && next !== ">" && source[index - 1] !== "<" && canStartRegexLiteral(out)) {
      const regexEnd = regexLiteralEnd(source, index);
      if (regexEnd !== -1) {
        out += maskSourceSegment(source, index, regexEnd);
        index = regexEnd;
        continue;
      }
    }
    out += ch;
    index += 1;
  }
  return out;
}

function canStartRegexLiteral(maskedPrefix) {
  let cursor = maskedPrefix.length - 1;
  while (cursor >= 0 && /\s/.test(maskedPrefix[cursor])) {
    cursor -= 1;
  }
  if (cursor < 0) {
    return true;
  }

  const ch = maskedPrefix[cursor];
  if ("({[=,:;?!&|+-*%^~<>".includes(ch)) {
    return true;
  }
  if (!/[A-Za-z0-9_$]/.test(ch)) {
    return false;
  }

  let start = cursor;
  while (start > 0 && /[A-Za-z0-9_$]/.test(maskedPrefix[start - 1])) {
    start -= 1;
  }
  return [
    "await",
    "case",
    "delete",
    "do",
    "else",
    "in",
    "instanceof",
    "of",
    "return",
    "throw",
    "typeof",
    "void",
    "yield",
  ].includes(maskedPrefix.slice(start, cursor + 1));
}

function regexLiteralEnd(source, start) {
  let cursor = start + 1;
  let inClass = false;
  while (cursor < source.length) {
    const ch = source[cursor];
    if (ch === "\n" || ch === "\r") {
      return -1;
    }
    if (ch === "\\") {
      cursor += 2;
      continue;
    }
    if (ch === "[") {
      inClass = true;
      cursor += 1;
      continue;
    }
    if (ch === "]" && inClass) {
      inClass = false;
      cursor += 1;
      continue;
    }
    if (ch === "/" && !inClass) {
      cursor += 1;
      while (cursor < source.length && /[A-Za-z]/.test(source[cursor])) {
        cursor += 1;
      }
      return cursor;
    }
    cursor += 1;
  }
  return -1;
}

function maskSourceSegment(source, start, end) {
  let out = "";
  for (let cursor = start; cursor < end; cursor += 1) {
    const ch = source[cursor];
    out += ch === "\n" || ch === "\r" ? ch : " ";
  }
  return out;
}

function isIdentifierChar(ch) {
  return /[A-Za-z0-9_$]/.test(ch);
}

function resolveSpecifier(specifier, parentURL) {
  if (specifier.startsWith("file:")) {
    return { fileUrl: specifier };
  }
  if (specifier.startsWith("node:") || specifier.startsWith("data:")) {
    return null;
  }

  if (specifier.startsWith(".") || specifier.startsWith("/")) {
    const parentDir = parentURL && parentURL.startsWith("file:") ? path.dirname(fileURLToPath(parentURL)) : PROJECT_DIR;
    return resolveCandidate(path.resolve(parentDir, specifier));
  }

  const pathLookupStart = TRACE_ENABLED ? process.hrtime.bigint() : 0n;
  const pathMatch = resolveTsconfigPath(specifier);
  if (TRACE_ENABLED) {
    traceEvent("tsconfig_paths", pathLookupStart, {
      specifier,
      hit: pathMatch !== null,
      result: pathMatch || "",
    });
  }
  if (pathMatch) {
    return pathMatch;
  }

  const baseUrl = compilerOptions.baseUrl;
  if (typeof baseUrl === "string" && baseUrl.length > 0) {
    const baseMatch = resolveCandidate(path.resolve(PROJECT_DIR, baseUrl, specifier));
    if (baseMatch) {
      return baseMatch;
    }
  }

  return null;
}

function resolveTsconfigPath(specifier) {
  const paths = compilerOptions.paths || {};
  const baseUrl = typeof compilerOptions.baseUrl === "string" ? compilerOptions.baseUrl : ".";
  const baseDir = path.resolve(PROJECT_DIR, baseUrl);

  for (const [pattern, targets] of Object.entries(paths)) {
    const match = matchPathPattern(pattern, specifier);
    if (!match) {
      continue;
    }
    const targetList = Array.isArray(targets) ? targets : [targets];
    for (const target of targetList) {
      if (typeof target !== "string") {
        continue;
      }
      const substituted = target.includes("*") ? target.replace("*", match.star || "") : target;
      const resolved = resolveCandidate(path.resolve(baseDir, substituted));
      if (resolved) {
        return resolved;
      }
    }
  }

  return null;
}

function matchPathPattern(pattern, specifier) {
  const star = pattern.indexOf("*");
  if (star === -1) {
    return pattern === specifier ? {} : null;
  }
  const prefix = pattern.slice(0, star);
  const suffix = pattern.slice(star + 1);
  if (!specifier.startsWith(prefix) || !specifier.endsWith(suffix)) {
    return null;
  }
  return { star: specifier.slice(prefix.length, specifier.length - suffix.length) };
}

function resolveCandidate(candidate) {
  if (isFile(candidate)) {
    return candidate;
  }
  for (const ext of JS_EXTS) {
    const withExt = `${candidate}${ext}`;
    if (isFile(withExt)) {
      return withExt;
    }
  }
  if (isDirectory(candidate)) {
    for (const ext of JS_EXTS) {
      const index = path.join(candidate, `index${ext}`);
      if (isFile(index)) {
        return index;
      }
    }
  }
  return null;
}

function isFile(candidate) {
  try {
    return fs.statSync(candidate).isFile();
  } catch (_error) {
    return false;
  }
}

function isDirectory(candidate) {
  try {
    return fs.statSync(candidate).isDirectory();
  } catch (_error) {
    return false;
  }
}

function traceEvent(phase, startNs, fields) {
  if (!TRACE_ENABLED) {
    return;
  }
  const event = {
    event: "lpm_ts_runtime",
    phase,
    pid: process.pid,
    durationNs: Number(process.hrtime.bigint() - startNs),
    ...fields,
  };
  traceWrite(`${JSON.stringify(event)}\n`);
}

function traceWrite(line) {
  if (TRACE_FILE) {
    try {
      if (traceFd === null) {
        traceFd = fs.openSync(TRACE_FILE, "a", 0o600);
        process.once("exit", closeTraceFile);
      }
      fs.writeSync(traceFd, line);
      return;
    } catch (_error) {
      TRACE_FILE = "";
    }
  }
  try {
    process.stderr.write(line);
  } catch (_error) {
    // Tracing is diagnostic-only; runtime behavior must not depend on stderr.
  }
}

function closeTraceFile() {
  if (traceFd === null) {
    return;
  }
  try {
    fs.closeSync(traceFd);
  } catch (_error) {
    // Ignore close failures for diagnostic trace output.
  }
  traceFd = null;
}
