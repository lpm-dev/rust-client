function hasOwn(value, key) { return Object.prototype.hasOwnProperty.call(value, key); }
function privateValue(key) {
  const descriptor = Object.getOwnPropertyDescriptor(globalThis.process?.env ?? Object.create(null), key);
  if (descriptor === undefined) return undefined;
  if (!hasOwn(descriptor, 'value')) throw new EnvError([{key,code:'env.invalid_value'}]);
  return descriptor.value;
}
const MAX_VALUE_BYTES = 1048576, MAX_INPUT_BYTES = 4194304, MAX_WORK = 10000000;

export class EnvError extends Error {
  constructor(issues) {
    super('Environment validation failed');
    this.name = 'EnvError';
    this.issues = Object.freeze(issues.map(issue => Object.freeze(issue)));
  }
}
function spend(work, amount = 1) {
  work.left -= amount;
  if (work.left < 0) throw new EnvError([{key:'envSchema',code:'env.resource_limit'}]);
}
function scan(value, work) {
  if (value.length > MAX_VALUE_BYTES) throw new EnvError([{key:'envSchema',code:'env.resource_limit'}]);
  let bytes = 0, scalars = 0, nul = false;
  for (let i = 0; i < value.length; i++) {
    spend(work);
    const c = value.charCodeAt(i);
    if (c === 0) nul = true;
    if (c >= 55296 && c <= 56319) {
      const next = value.charCodeAt(++i);
      if (!(next >= 56320 && next <= 57343)) return null;
      bytes += 4;
    } else {
      if (c >= 56320 && c <= 57343) return null;
      bytes += c < 128 ? 1 : c < 2048 ? 2 : 3;
    }
    scalars++;
    if (bytes > MAX_VALUE_BYTES) throw new EnvError([{key:'envSchema',code:'env.resource_limit'}]);
  }
  return {bytes,scalars,nul};
}

function asciiWord(c) { return c >= 48 && c <= 57 || c >= 65 && c <= 90 || c >= 97 && c <= 122 || c === 95; }
function unicodeWord(c, work) {
  let low = 0, high = wordRanges.length - 1;
  while (low <= high) {
    spend(work);
    const mid = (low + high) >>> 1, range = wordRanges[mid];
    if (c < range[0]) high = mid - 1;
    else if (c > range[1]) low = mid + 1;
    else return true;
  }
  return false;
}
function scalar(bytes, p) {
  const c = bytes[p];
  if (c < 128) return c;
  if (c < 224) return ((c & 31) << 6) | (bytes[p + 1] & 63);
  if (c < 240) return ((c & 15) << 12) | ((bytes[p + 1] & 63) << 6) | (bytes[p + 2] & 63);
  return ((c & 7) << 18) | ((bytes[p + 1] & 63) << 12) | ((bytes[p + 2] & 63) << 6) | (bytes[p + 3] & 63);
}
function patternMatch(program, bytes, scratch, work) {
  const {states,start} = program;
  let current = scratch.current, next = scratch.next, active = 0, pending = 0, nextCount = 0;
  const marks = scratch.marks, stack = scratch.stack;
  let stamp = scratch.stamp;
  let position = 0, boundary = true, leftUnicode = false, rightUnicode = false, unicodeReady = false;
  function begin() {
    stamp = (stamp + 1) >>> 0;
    if (stamp === 0) { marks.fill(0); stamp = 1; }
    pending = 0; nextCount = 0; unicodeReady = false;
    boundary = position === bytes.length || (bytes[position] & 192) !== 128;
  }
  function unicodeSides() {
    if (unicodeReady) return;
    unicodeReady = true;
    if (!boundary) return;
    let previous = position - 1;
    while (previous > 0 && (bytes[previous] & 192) === 128) previous--;
    leftUnicode = position > 0 && unicodeWord(scalar(bytes, previous), work);
    rightUnicode = position < bytes.length && unicodeWord(scalar(bytes, position), work);
  }
  function look(tag) {
    const left = asciiWord(bytes[position - 1]), right = asciiWord(bytes[position]);
    switch (tag) {
      case 0: return position === 0;
      case 1: return position === bytes.length;
      case 2: return position === 0 || bytes[position - 1] === 10;
      case 3: return position === bytes.length || bytes[position] === 10;
      case 4: return position === 0 || bytes[position - 1] === 10 || bytes[position - 1] === 13 && bytes[position] !== 10;
      case 5: return position === bytes.length || bytes[position] === 13 || bytes[position] === 10 && bytes[position - 1] !== 13;
      case 6: return left !== right;
      case 7: return left === right;
      case 10: return !left && right;
      case 11: return left && !right;
      case 14: return !left;
      case 15: return !right;
      default:
        if (!boundary) return false;
        unicodeSides();
        switch (tag) {
          case 8: return leftUnicode !== rightUnicode;
          case 9: return leftUnicode === rightUnicode;
          case 12: return !leftUnicode && rightUnicode;
          case 13: return leftUnicode && !rightUnicode;
          case 16: return !leftUnicode;
          case 17: return !rightUnicode;
          default: throw new EnvError([{key:'envSchema',code:'env.engine_invalid'}]);
        }
    }
  }
  function schedule(id) {
    spend(work);
    if (marks[id] !== stamp) { marks[id] = stamp; stack[pending++] = id; }
  }
  function closure(id) {
    schedule(id);
    while (pending > 0) {
      const index = stack[--pending], state = states[index];
      switch (state[0]) {
        case 0: next[nextCount++] = index; break;
        case 1: if (look(state[1])) schedule(state[2]); break;
        case 2: for (const target of state[1]) schedule(target); break;
        case 3: break;
        case 4: if (boundary) return true; break;
        default: throw new EnvError([{key:'envSchema',code:'env.engine_invalid'}]);
      }
    }
    return false;
  }
  begin();
  if (closure(start)) { scratch.stamp = stamp; return true; }
  let temporary = current; current = next; next = temporary; active = nextCount;
  for (position = 1; position <= bytes.length; position++) {
    begin();
    const byte = bytes[position - 1];
    for (let i = 0; i < active; i++) {
      const ranges = states[current[i]][1];
      let low = 0, high = ranges.length - 1;
      while (low <= high) {
        spend(work);
        const mid = (low + high) >>> 1, range = ranges[mid];
        if (byte < range[0]) high = mid - 1;
        else if (byte > range[1]) low = mid + 1;
        else {
          if (closure(range[2])) { scratch.stamp = stamp; return true; }
          break;
        }
      }
    }
    temporary = current; current = next; next = temporary; active = nextCount;
    if (active === 0) break;
  }
  scratch.stamp = stamp; return false;
}

export function createEnv(input) {
  const work = {left:MAX_WORK}, raw = Object.create(null), output = Object.create(null), lengths = Object.create(null), issues = [];
  const issue = (key,code,constraint) => issues.push(constraint === undefined ? {key,code} : {key,code,constraint});
  let total = 0;
  const invalid = new Set();
  for (const rule of rules) {
    spend(work);
    let descriptor;
    try { descriptor = Object.getOwnPropertyDescriptor(input, rule.key); }
    catch { invalid.add(rule.key); issue(rule.key,'env.invalid_value'); continue; }
    if (descriptor !== undefined) {
      if (!hasOwn(descriptor, 'value') || descriptor.value !== undefined && typeof descriptor.value !== 'string') {
        invalid.add(rule.key); issue(rule.key,'env.invalid_value'); continue;
      }
      if (descriptor.value !== undefined) raw[rule.key] = descriptor.value;
    }
    if ((raw[rule.key] === undefined || raw[rule.key] === '' && rule.empty === 'missing') && rule.default !== null) raw[rule.key] = rule.default;
    if (raw[rule.key] !== undefined) {
      const info = scan(raw[rule.key], work);
      if (info === null || info.nul) { invalid.add(rule.key); issue(rule.key,'env.invalid_value'); }
      else {
        total += info.bytes;
        if (total > MAX_INPUT_BYTES) throw new EnvError([{key:'envSchema',code:'env.resource_limit'}]);
        lengths[rule.key] = info.scalars;
      }
    }
  }
  let largest = 0;
  for (const program of programs) largest = Math.max(largest, program.states.length);
  const scratch = {current:new Uint32Array(largest),next:new Uint32Array(largest),marks:new Uint32Array(largest),stack:new Uint32Array(largest),stamp:0};
  for (const rule of rules) {
    spend(work);
    const {key} = rule, value = raw[key];
    output[key] = undefined;
    if (invalid.has(key)) continue;
    const condition = rule.condition;
    if (!rule.required && condition !== null && hasOwn(condition,'equals')) {
      spend(work, 1 + Math.min(condition.equals.length, raw[condition.variable]?.length ?? 0));
    }
    const required = rule.required || condition !== null && (hasOwn(condition,'equals') ? raw[condition.variable] === condition.equals : (raw[condition.variable] !== undefined && raw[condition.variable] !== '') === condition.present);
    if (value === '' && rule.empty === 'reject') { issue(key,'env.empty'); continue; }
    if (value === undefined || value === '' && (required || rule.empty === 'missing')) {
      if (required) issue(key,'env.required');
      continue;
    }
    spend(work, value.length);
    const parsed = converted(value, rule.format, work);
    if (parsed === null) { issue(key,'env.invalid_format'); continue; }
    let constraint;
    if (rule.min !== null && parsed < BigInt(rule.min)) constraint = 'min';
    else if (rule.max !== null && parsed > BigInt(rule.max)) constraint = 'max';
    else if (rule.min_length !== null && lengths[key] < rule.min_length) constraint = 'minLength';
    else if (rule.max_length !== null && lengths[key] > rule.max_length) constraint = 'maxLength';
    else if (rule.protocols !== null && !rule.protocols.includes(value.slice(0,value.indexOf(':')).toLowerCase())) constraint = 'protocols';
    if (constraint !== undefined) { issue(key,'env.constraint',constraint); continue; }
    if (rule.pattern !== null && !patternMatch(programs[rule.pattern], new TextEncoder().encode(value), scratch, work)) { issue(key,'env.pattern_mismatch'); continue; }
    if (rule.values !== null) {
      let found = false;
      for (const allowed of rule.values) { spend(work, 1 + Math.min(allowed.length,value.length)); if (allowed === value) { found = true; break; } }
      if (!found) { issue(key,'env.enum_mismatch'); continue; }
    }
    output[key] = parsed;
  }
  for (const [name,group] of groups) {
    let present = 0;
    for (const key of group.vars) { spend(work); if (raw[key] !== undefined && raw[key] !== '') present++; }
    if (!(group.mode === 'allOrNone' ? present === 0 || present === group.vars.length : group.mode === 'exactlyOne' ? present === 1 : present > 0)) {
      for (const key of group.vars) issue(key,'env.group',name);
    }
  }
  if (issues.length > 0) {
    issues.sort((a,b) => a.key < b.key ? -1 : a.key > b.key ? 1 : 0);
    throw new EnvError(issues);
  }
  return Object.freeze(output);
}
