function whitespace(c) {
  return c <= 32 || c >= 127 && c <= 160 || c === 5760 || c >= 8192 && c <= 8202 || c === 8232 || c === 8233 || c === 8239 || c === 8287 || c === 12288;
}
function urlRegion(value, start, end, work) {
  for (let i = start; i < end; i++) {
    spend(work);
    const c = value.codePointAt(i);
    if (c === 37) {
      if (i + 2 >= end || !hex(value.charCodeAt(i + 1)) || !hex(value.charCodeAt(i + 2))) return false;
    }
    if (c > 65535) i++;
  }
  return true;
}
function validDatabaseEndpoint(endpoint, work) {
  let host, port;
  if (endpoint.startsWith('[')) {
    const close = endpoint.indexOf(']');
    if (close < 0 || !endpoint.slice(1, close).includes(':') || !ip(endpoint.slice(1, close))) return false;
    host = endpoint.slice(0, close + 1);
    const suffix = endpoint.slice(close + 1);
    if (suffix === '') return true;
    if (suffix[0] !== ':') return false;
    port = suffix.slice(1);
  } else {
    const colon = endpoint.lastIndexOf(':');
    host = colon < 0 ? endpoint : endpoint.slice(0, colon);
    port = colon < 0 ? undefined : endpoint.slice(colon + 1);
  }
  if (host === '' || !host.startsWith('[') && host.includes(':')) return false;
  if (port !== undefined) {
    if (port === '') return false;
    let number = 0;
    for (let i = 0; i < port.length; i++) {
      spend(work);
      const digit = port.charCodeAt(i) - 48;
      if (digit < 0 || digit > 9) return false;
      number = number * 10 + digit;
      if (number > 65535) return false;
    }
  }
  if (!boundedPlatformHost(host,true,work)) return false;
  spend(work,host.length);
  let parsed;
  try { parsed = new URL('http://' + host); }
  catch { return false; }
  return parsed.hostname.length > 0 && validBidiDomain(parsed.hostname,work);
}
const BIDI_LTR = 1, BIDI_RTL = 2, BIDI_AN = 4, BIDI_EN = 8, BIDI_NSM = 16, BIDI_NEUTRAL = 32;
function decodeRanges(encoded) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  const values = [], triples = [];
  let value = 0, shift = 0, previous = 0;
  for (let i = 0; i < encoded.length; i++) {
    const digit = alphabet.indexOf(encoded[i]);
    value += (digit & 31) * 2 ** shift;
    if (digit & 32) shift += 5;
    else {
      values.push(value); value = 0; shift = 0;
      if (values.length === 3) {
        const start = previous + values[0], end = start + values[1];
        triples.push(start,end,values[2]); previous = end + 1; values.length = 0;
      }
    }
  }
  return new Uint32Array(triples);
}
function rangeClass(c, ranges, fallback, work) {
  let low = 0, high = ranges.length / 3 - 1;
  while (low <= high) {
    spend(work);
    const mid = (low + high) >>> 1, offset = mid * 3;
    if (c < ranges[offset]) high = mid - 1;
    else if (c > ranges[offset + 1]) low = mid + 1;
    else return ranges[offset + 2];
  }
  return fallback;
}
function bidiClass(c, work) { return rangeClass(c,bidiRanges,BIDI_LTR,work); }
function validJoiners(scalars, work) {
  for (let i = 0; i < scalars.length; i++) {
    spend(work);
    const c = scalars[i];
    if (c !== 8204 && c !== 8205) continue;
    if (i === 0) return false;
    if (rangeClass(scalars[i - 1],viramaRanges,0,work)) continue;
    if (c === 8205) return false;
    let before = i - 1, after = i + 1, left, right;
    do { left = rangeClass(scalars[before--],joiningRanges,0,work); } while (left === 4 && before >= 0);
    do { right = after < scalars.length ? rangeClass(scalars[after++],joiningRanges,0,work) : 0; } while (right === 4);
    if (!(left & 1) || !(right & 2)) return false;
  }
  return true;
}
function boundedPlatformHost(host, idna, work) {
  // Reserve quadratic IDNA work before the platform parser can allocate or encode a label.
  spend(work,host.length);
  if (!idna || host.startsWith('[')) return true;
  let decoded;
  try { decoded = decodeURIComponent(host); } catch { return false; }
  const colon = decoded.lastIndexOf(':');
  if (colon >= 0) decoded = decoded.slice(0,colon);
  for (const label of decoded.split(/[.\u3002\uff0e\uff61]/u)) {
    let count = 0, nonAscii = false;
    for (const character of label) { spend(work); count++; nonAscii ||= character.codePointAt(0) > 127; }
    if (label.toLowerCase().startsWith('xn--') && label.length > 2004) return false;
    if (nonAscii) spend(work,count * count);
  }
  return true;
}
function punycodeLabel(label, work) {
  if (!label.startsWith('xn--')) return Array.from(label,c=>c.codePointAt(0));
  const input = label.slice(4), output = [], delimiter = input.lastIndexOf('-');
  if (input.length === 0 || input.length > 2000 || delimiter === 0) return null;
  let position = 0, n = 128, i = 0, bias = 72;
  if (delimiter >= 0) {
    for (; position < delimiter; position++) {
      spend(work);
      const c = input.charCodeAt(position);
      if (c > 127) return null;
      output.push(c);
    }
    position++;
  }
  while (position < input.length) {
    const previous = i;
    let weight = 1;
    for (let k = 36; ; k += 36) {
      spend(work);
      if (position >= input.length) return null;
      const c = input.charCodeAt(position++);
      const digit = c >= 97 && c <= 122 ? c - 97 : c >= 48 && c <= 57 ? c - 22 : 36;
      if (digit >= 36) return null;
      i += digit * weight;
      if (!Number.isSafeInteger(i)) return null;
      const threshold = k <= bias ? 1 : k >= bias + 26 ? 26 : k - bias;
      if (digit < threshold) break;
      weight *= 36 - threshold;
      if (!Number.isSafeInteger(weight)) return null;
    }
    const count = output.length + 1;
    if (count > 1000) return null;
    let delta = Math.floor((i - previous) / (previous === 0 ? 700 : 2));
    delta += Math.floor(delta / count);
    let k = 0;
    while (delta > 455) { spend(work); delta = Math.floor(delta / 35); k += 36; }
    bias = k + Math.floor(36 * delta / (delta + 38));
    n += Math.floor(i / count);
    if (n > 1114111 || n >= 55296 && n <= 57343) return null;
    i %= count;
    // Charge insertion shifts before allocating or moving decoded scalars.
    spend(work,output.length - i + 1);
    output.splice(i,0,n);
    i++;
  }
  return output.length > 1000 || output.every(c=>c < 128) ? null : output;
}
function validBidiDomain(host, work) {
  if (host.startsWith('[') || !host.includes('xn--')) return true;
  const labels = [], parts = host.split('.');
  let triggered = false;
  for (const part of parts) {
    spend(work,part.length + 1);
    const scalars = punycodeLabel(part,work);
    if (scalars === null || !validJoiners(scalars,work)) return false;
    const classes = scalars.map(c=>bidiClass(c,work));
    for (const c of classes) { spend(work); if (c & (BIDI_RTL | BIDI_AN)) triggered = true; }
    labels.push(classes);
  }
  if (!triggered) return true;
  for (const classes of labels) {
    if (classes.length === 0) continue;
    const first = classes[0];
    if (!(first & (BIDI_LTR | BIDI_RTL))) return false;
    const ltr = first === BIDI_LTR;
    const allowed = (ltr ? BIDI_LTR : BIDI_RTL | BIDI_AN) | BIDI_EN | BIDI_NSM | BIDI_NEUTRAL;
    const lastAllowed = (ltr ? BIDI_LTR : BIDI_RTL | BIDI_AN) | BIDI_EN;
    let last = classes.length - 1, numerals = 0;
    while (last > 0 && classes[last] === BIDI_NSM) { spend(work); last--; }
    if (!(classes[last] & lastAllowed)) return false;
    for (let j = 1; j <= last; j++) {
      spend(work);
      const c = classes[j];
      if (!(c & allowed)) return false;
      numerals |= c & (BIDI_AN | BIDI_EN);
    }
    if (!ltr && numerals === (BIDI_AN | BIDI_EN)) return false;
  }
  return true;
}
function fileDriveSegment(path) {
  const c = path.charCodeAt(1);
  return path[0] === '/' && (c >= 65 && c <= 90 || c >= 97 && c <= 122) &&
    (path[2] === ':' || path[2] === '|') && (path.length === 3 || '/?#'.includes(path[3]));
}
function parsedUrl(value, work) {
  const schemeEnd = value.indexOf(':'), start = schemeEnd + 3;
  const scheme = value.slice(0, schemeEnd).toLowerCase();
  const special = ['http','https','ftp','ws','wss','file'].includes(scheme);
  if (special && value.split(/[?#]/,1)[0].includes('\\')) return false;
  let end = start;
  while (end < value.length && !'/?#'.includes(value[end])) end++;
  const authority = value.slice(start,end), at = authority.lastIndexOf('@');
  if (at >= 0 && !urlRegion(authority,0,at,work)) return false;
  const hash = value.indexOf('#',end);
  if (!urlRegion(value,end,hash < 0 ? value.length : hash,work) ||
      hash >= 0 && !urlRegion(value,hash + 1,value.length,work)) return false;
  if (scheme === 'file') {
    if (authority.toLowerCase() === 'localhost' || at >= 0) return false;
    const path = value.slice(end);
    if (fileDriveSegment(path)) return false;
  }
  if (!boundedPlatformHost(authority.slice(at + 1),special,work)) return false;
  spend(work,value.length);
  let parsed;
  try { parsed = new URL(value); }
  catch { return false; }
  if (scheme === 'file' && fileDriveSegment(parsed.pathname)) return false;
  return parsed.hostname.length > 0 && (!special || validBidiDomain(parsed.hostname,work));
}
function url(value, work) {
  const schemeEnd = value.indexOf(':');
  if (schemeEnd < 1 || value.slice(schemeEnd,schemeEnd + 3) !== '://') return false;
  for (let i = 0; i < value.length; i++) {
    spend(work);
    const c = value.codePointAt(i);
    if (whitespace(c)) return false;
    if (c > 65535) i++;
  }
  const scheme = value.slice(0,schemeEnd).toLowerCase();
  const special = ['http','https','ftp','ws','wss','file'].includes(scheme);
  const start = schemeEnd + 3;
  let end = start;
  while (end < value.length && !'/?#'.includes(value[end])) end++;
  const authority = value.slice(start,end), at = authority.lastIndexOf('@');
  const hosts = authority.slice(at + 1);
  if (hosts === '' || [...'\\^{}|\"<>`'].some(c=>hosts.includes(c))) return false;
  let candidate = value;
  if (hosts.includes(',')) {
    if (special) return false;
    let previous = 0;
    for (let i = 0; i <= hosts.length; i++) {
      spend(work);
      if (i === hosts.length || hosts[i] === ',') {
        if (!validDatabaseEndpoint(hosts.slice(previous,i),work)) return false;
        previous = i + 1;
      }
    }
    candidate = value.slice(0,start + at + 1) + hosts.slice(0,hosts.indexOf(',')) + value.slice(end);
  }
  return parsedUrl(candidate,work);
}

