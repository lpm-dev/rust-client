const crypto = require("node:crypto");
const fs = require("node:fs");
const moduleApi = require("node:module");
const path = require("node:path");
const { pathToFileURL, fileURLToPath } = require("node:url");

const RUNTIME_VERSION = "1";
const TS_EXT_RE = /\.(?:ts|tsx|mts|cts)$/;
const JS_EXTS = [".ts", ".tsx", ".mts", ".cts", ".js", ".mjs", ".cjs", ".json"];
const PROJECT_DIR = path.resolve(process.env.LPM_TS_RUNTIME_PROJECT_DIR || process.cwd());
const CACHE_DIR =
  process.env.LPM_TS_RUNTIME_CACHE_DIR ||
  path.join(PROJECT_DIR, ".lpm", "exec-ts-runtime-cache");

if (typeof moduleApi.registerHooks !== "function") {
  throw new Error("LPM TS runtime requires Node.js module.registerHooks support. Run `lpm use node@22.18+`.");
}

if (typeof moduleApi.stripTypeScriptTypes !== "function") {
  throw new Error("LPM TS runtime requires Node.js module.stripTypeScriptTypes support. Run `lpm use node@22.18+`.");
}

const tsconfig = loadTsconfig(PROJECT_DIR);
const tsconfigFingerprint = hashJson(tsconfig.compilerOptions || {});

moduleApi.registerHooks({
  resolve(specifier, context, nextResolve) {
    const mapped = resolveSpecifier(specifier, context.parentURL);
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

    const source = fs.readFileSync(filename, "utf8");
    const format = moduleFormat(filename, source);
    return {
      format,
      source: loadTransformedSource(filename, source, format),
      shortCircuit: true,
    };
  },
});

function loadTransformedSource(filename, source, format) {
  const key = cacheKey(filename, source, format);
  const cachePath = path.join(CACHE_DIR, `${key}.${format === "commonjs" ? "cjs" : "mjs"}`);

  try {
    return fs.readFileSync(cachePath, "utf8");
  } catch (error) {
    if (!error || error.code !== "ENOENT") {
      throw error;
    }
  }

  const transformed = transformSource(filename, source);
  fs.mkdirSync(CACHE_DIR, { recursive: true });
  const tmp = `${cachePath}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, transformed);
  fs.renameSync(tmp, cachePath);
  return transformed;
}

function transformSource(filename, source) {
  let transformed = source;
  if (filename.endsWith(".tsx")) {
    transformed = transformTsx(transformed);
  }
  return moduleApi.stripTypeScriptTypes(transformed, {
    mode: "transform",
    sourceMap: true,
    sourceUrl: filename,
  });
}

function cacheKey(filename, source, format) {
  const hash = crypto.createHash("sha256");
  hash.update(RUNTIME_VERSION);
  hash.update("\0");
  hash.update(process.versions.node);
  hash.update("\0");
  hash.update(process.platform);
  hash.update("\0");
  hash.update(process.arch);
  hash.update("\0");
  hash.update(format);
  hash.update("\0");
  hash.update(filename);
  hash.update("\0");
  hash.update(tsconfigFingerprint);
  hash.update("\0");
  hash.update(source);
  return hash.digest("hex");
}

function hashJson(value) {
  return crypto.createHash("sha256").update(JSON.stringify(value || {})).digest("hex");
}

function loadTsconfig(projectDir) {
  const tsconfigPath = path.join(projectDir, "tsconfig.json");
  try {
    const text = fs.readFileSync(tsconfigPath, "utf8");
    return JSON.parse(stripJsonComments(text));
  } catch (_error) {
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
  if (hasEsmSyntax(source)) {
    return "module";
  }
  return "commonjs";
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
  for (const line of sourceWithoutCommentsAndStrings(source).split(/\r?\n/)) {
    const trimmed = line.trimStart();
    if (trimmed.startsWith("import") && importStatementHasRuntime(trimmed)) {
      return true;
    }
    if (trimmed.startsWith("export") && exportStatementHasRuntime(trimmed)) {
      return true;
    }
  }
  return false;
}

function sourceWithoutCommentsAndStrings(source) {
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
    out += ch;
    index += 1;
  }
  return out;
}

function importStatementHasRuntime(statement) {
  if (/^import\s+type\b/.test(statement)) {
    return false;
  }
  if (/^import\s+\w+\s*=/.test(statement)) {
    return false;
  }
  const named = statement.match(/^import\s*\{([^}]*)\}\s*from\b/);
  if (named) {
    return !allTypeSpecifiers(named[1]);
  }
  return /^import(?:\s|["'])/.test(statement);
}

function exportStatementHasRuntime(statement) {
  if (/^export\s+(?:type|interface|declare)\b/.test(statement)) {
    return false;
  }
  if (/^export\s*=/.test(statement)) {
    return false;
  }
  const named = statement.match(/^export\s*\{([^}]*)\}/);
  if (named && allTypeSpecifiers(named[1])) {
    return false;
  }
  return /^export(?:\s|\*)/.test(statement);
}

function allTypeSpecifiers(specifiers) {
  const parts = specifiers
    .split(",")
    .map((part) => part.trim())
    .filter(Boolean);
  return parts.length > 0 && parts.every((part) => part === "type" || part.startsWith("type "));
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

  const pathMatch = resolveTsconfigPath(specifier);
  if (pathMatch) {
    return pathMatch;
  }

  const baseUrl = tsconfig.compilerOptions && tsconfig.compilerOptions.baseUrl;
  if (typeof baseUrl === "string" && baseUrl.length > 0) {
    const baseMatch = resolveCandidate(path.resolve(PROJECT_DIR, baseUrl, specifier));
    if (baseMatch) {
      return baseMatch;
    }
  }

  return null;
}

function resolveTsconfigPath(specifier) {
  const options = tsconfig.compilerOptions || {};
  const paths = options.paths || {};
  const baseUrl = typeof options.baseUrl === "string" ? options.baseUrl : ".";
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

function transformTsx(source) {
  const parser = new TsxParser(source);
  const body = parser.transform();
  if (!parser.sawJsx) {
    return body;
  }
  return `${jsxHelper()}\n${body}`;
}

function jsxHelper() {
  return "const __lpmJsx = globalThis.__lpmJsx || (globalThis.__lpmJsx = (type, props, ...children) => { const react = globalThis.React && globalThis.React.createElement; return react ? react(type, props, ...children) : ({ type, props: props || {}, children }); });";
}

class TsxParser {
  constructor(source) {
    this.source = source;
    this.index = 0;
    this.sawJsx = false;
  }

  transform() {
    let out = "";
    while (this.index < this.source.length) {
      if (this.startsJsx()) {
        this.sawJsx = true;
        out += this.parseElement();
      } else {
        out += this.source[this.index];
        this.index += 1;
      }
    }
    return out;
  }

  startsJsx(inChildren = false) {
    const ch = this.source[this.index];
    const next = this.source[this.index + 1];
    if (ch !== "<") {
      return false;
    }
    if (next === ">") {
      return inChildren || this.canStartJsxExpression();
    }
    if (!/[A-Za-z]/.test(next || "")) {
      return false;
    }
    return inChildren || (this.canStartJsxExpression() && this.looksLikeJsxTag());
  }

  canStartJsxExpression() {
    const prev = this.previousSignificantIndex();
    if (prev === -1) {
      return true;
    }

    const ch = this.source[prev];
    if ("({[=,:;?!&|+-*%^~".includes(ch)) {
      return true;
    }
    if (ch === ">" && this.source[prev - 1] === "=") {
      return true;
    }

    return ["return", "throw", "yield", "await", "case"].includes(this.previousWordAt(prev));
  }

  previousSignificantIndex() {
    let cursor = this.index - 1;
    while (cursor >= 0 && /\s/.test(this.source[cursor])) {
      cursor -= 1;
    }
    return cursor;
  }

  previousWordAt(index) {
    if (!/[A-Za-z0-9_$]/.test(this.source[index] || "")) {
      return "";
    }
    let start = index;
    while (start > 0 && /[A-Za-z0-9_$]/.test(this.source[start - 1])) {
      start -= 1;
    }
    return this.source.slice(start, index + 1);
  }

  looksLikeJsxTag() {
    if (this.peekAhead("<>")) {
      return true;
    }
    let cursor = this.index + 1;
    while (cursor < this.source.length && /[A-Za-z0-9_$:.-]/.test(this.source[cursor])) {
      cursor += 1;
    }
    const delimiter = this.source[cursor] || "";
    return delimiter === ">" || delimiter === "/" || /\s/.test(delimiter);
  }

  parseElement() {
    this.expect("<");
    if (this.peek() === ">") {
      this.index += 1;
      const children = this.parseChildren("");
      return `__lpmJsx(${JSON.stringify("Fragment")}, null${children})`;
    }

    const tag = this.readTagName();
    const attrs = this.readAttributes();
    if (this.peekAhead("/>")) {
      this.index += 2;
      return `__lpmJsx(${tagExpression(tag)}, ${attrs})`;
    }
    this.expect(">");
    const children = this.parseChildren(tag);
    return `__lpmJsx(${tagExpression(tag)}, ${attrs}${children})`;
  }

  parseChildren(tag) {
    const children = [];
    let closed = false;
    while (this.index < this.source.length) {
      if (tag && this.peekAhead(`</${tag}>`)) {
        this.index += tag.length + 3;
        closed = true;
        break;
      }
      if (!tag && this.peekAhead("</>")) {
        this.index += 3;
        closed = true;
        break;
      }
      if (this.peekAhead("</")) {
        throw new Error(`Invalid TSX near offset ${this.index}: unexpected closing tag`);
      }
      if (this.startsJsx(true)) {
        children.push(this.parseElement());
        continue;
      }
      if (this.peek() === "{") {
        const expr = this.readBalanced("{", "}");
        const inner = expr.slice(1, -1).trim();
        if (this.hasExpressionValue(inner)) {
          children.push(this.transformExpression(inner));
        }
        continue;
      }
      const text = this.readTextChild();
      const normalized = text.replace(/\s+/g, " ").trim();
      if (normalized) {
        children.push(JSON.stringify(normalized));
      }
    }
    if (!closed) {
      const closing = tag ? `</${tag}>` : "</>";
      throw new Error(`Invalid TSX near offset ${this.index}: expected ${closing}`);
    }
    return children.length ? `, ${children.join(", ")}` : "";
  }

  readAttributes() {
    const pieces = [];
    while (this.index < this.source.length) {
      this.skipWhitespace();
      if (this.peekAhead("/>") || this.peek() === ">") {
        break;
      }
      if (this.peekAhead("{...")) {
        const spread = this.readBalanced("{", "}").slice(4, -1).trim();
        if (spread) {
          pieces.push(this.transformExpression(spread));
        }
        continue;
      }

      const name = this.readAttrName();
      if (!name) {
        break;
      }
      this.skipWhitespace();
      let value = "true";
      if (this.peek() === "=") {
        this.index += 1;
        this.skipWhitespace();
        value = this.readAttrValue();
      }
      pieces.push(`{ ${JSON.stringify(name)}: ${value} }`);
    }

    if (!pieces.length) {
      return "null";
    }
    return `Object.assign({}, ${pieces.join(", ")})`;
  }

  readAttrValue() {
    const quote = this.peek();
    if (quote === "\"" || quote === "'") {
      this.index += 1;
      let value = "";
      while (this.index < this.source.length && this.peek() !== quote) {
        value += this.source[this.index];
        this.index += 1;
      }
      this.expect(quote);
      return JSON.stringify(value);
    }
    if (quote === "{") {
      const expression = this.readBalanced("{", "}").slice(1, -1).trim();
      return expression ? this.transformExpression(expression) : "undefined";
    }
    if (this.startsJsx()) {
      return this.parseElement();
    }
    return this.readAttrName() || "undefined";
  }

  readTextChild() {
    let text = "";
    while (this.index < this.source.length) {
      if (this.startsJsx(true) || this.peek() === "{" || this.peekAhead("</")) {
        break;
      }
      text += this.source[this.index];
      this.index += 1;
    }
    return text;
  }

  transformExpression(expression) {
    const parser = new TsxParser(expression);
    const transformed = parser.transform();
    this.sawJsx = this.sawJsx || parser.sawJsx;
    return transformed;
  }

  hasExpressionValue(expression) {
    let cursor = 0;
    while (cursor < expression.length) {
      if (/\s/.test(expression[cursor])) {
        cursor += 1;
        continue;
      }
      if (expression.startsWith("/*", cursor)) {
        const end = expression.indexOf("*/", cursor + 2);
        if (end === -1) {
          return false;
        }
        cursor = end + 2;
        continue;
      }
      if (expression.startsWith("//", cursor)) {
        const lineFeed = expression.indexOf("\n", cursor + 2);
        const carriageReturn = expression.indexOf("\r", cursor + 2);
        const ends = [lineFeed, carriageReturn].filter((index) => index !== -1);
        const end = ends.length ? Math.min(...ends) : -1;
        if (end === -1) {
          return false;
        }
        cursor = end + 1;
        continue;
      }
      return true;
    }
    return false;
  }

  readBalanced(open, close) {
    this.expect(open);
    let depth = 1;
    let out = open;
    let quote = null;
    while (this.index < this.source.length && depth > 0) {
      const ch = this.source[this.index];
      out += ch;
      this.index += 1;
      if (quote) {
        if (ch === "\\") {
          out += this.source[this.index] || "";
          this.index += 1;
        } else if (ch === quote) {
          quote = null;
        }
        continue;
      }
      if (ch === "\"" || ch === "'" || ch === "`") {
        quote = ch;
      } else if (ch === open) {
        depth += 1;
      } else if (ch === close) {
        depth -= 1;
      }
    }
    return out;
  }

  readTagName() {
    let name = "";
    while (this.index < this.source.length && /[A-Za-z0-9_$:.-]/.test(this.peek())) {
      name += this.peek();
      this.index += 1;
    }
    return name;
  }

  readAttrName() {
    let name = "";
    while (this.index < this.source.length && /[A-Za-z0-9_$:.-]/.test(this.peek())) {
      name += this.peek();
      this.index += 1;
    }
    return name;
  }

  skipWhitespace() {
    while (/\s/.test(this.peek() || "")) {
      this.index += 1;
    }
  }

  peek() {
    return this.source[this.index];
  }

  peekAhead(text) {
    return this.source.startsWith(text, this.index);
  }

  expect(text) {
    if (!this.peekAhead(text)) {
      throw new Error(`Invalid TSX near offset ${this.index}: expected ${text}`);
    }
    this.index += text.length;
  }
}

function tagExpression(tag) {
  if (!tag || /^[a-z]/.test(tag) || tag.includes("-") || tag.includes(":")) {
    return JSON.stringify(tag);
  }
  return tag;
}
