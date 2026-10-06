function decimal(value, port) {
  let p = 0, negative = false;
  if (value[0] === '+' || value[0] === '-') {
    negative = value[0] === '-'; p++;
  }
  if (p === value.length || (port && negative)) return null;
  let first = -1;
  for (let i = p; i < value.length; i++) {
    const c = value.charCodeAt(i);
    if (c < 48 || c > 57) return null;
    if (first < 0 && c !== 48) first = i;
  }
  const digits = first < 0 ? '0' : value.slice(first);
  const bound = port ? '65535' : negative ? '9223372036854775808' : '9223372036854775807';
  if (digits.length > bound.length || (digits.length === bound.length && digits > bound)) return null;
  if (port) return digits === '0' ? null : Number(digits);
  return BigInt((negative ? '-' : '') + digits);
}

function bool(value) {
  if (value === '1') return true;
  if (value === '0') return false;
  if (value.length > 5) return null;
  const lower = value.toLowerCase();
  if (lower === 'true' || lower === 'yes') return true;
  if (lower === 'false' || lower === 'no') return false;
  return null;
}

function hostname(value) {
  if (value.length === 0 || value.length > 253) return false;
  let start = 0;
  for (let i = 0; i <= value.length; i++) {
    const c = value.charCodeAt(i);
    if (i === value.length || c === 46) {
      if (i === start || i - start > 63 || value[start] === '-' || value[i - 1] === '-') return false;
      start = i + 1;
    } else if (!(c >= 48 && c <= 57 || c >= 65 && c <= 90 || c >= 97 && c <= 122 || c === 45)) return false;
  }
  return true;
}

function email(value) {
  if (value.length > 254) return false;
  const at = value.indexOf('@');
  if (at < 1 || at > 64 || value[0] === '.' || value[at - 1] === '.') return false;
  for (let i = 0; i < at; i++) {
    const c = value.charCodeAt(i);
    if (c > 127 || !(c >= 48 && c <= 57 || c >= 65 && c <= 90 || c >= 97 && c <= 122 || ".!#$%&'*+-/=?^_`{|}~".includes(value[i]))) return false;
    if (value[i] === '.' && value[i + 1] === '.') return false;
  }
  const domain = value.slice(at + 1);
  return domain.includes('.') && hostname(domain);
}

function ipv4(value) {
  let start = 0, parts = 0;
  for (let i = 0; i <= value.length; i++) {
    if (i === value.length || value[i] === '.') {
      const length = i - start;
      if (length < 1 || length > 3 || length > 1 && value[start] === '0') return false;
      let n = 0;
      for (let j = start; j < i; j++) {
        const c = value.charCodeAt(j) - 48;
        if (c < 0 || c > 9) return false;
        n = n * 10 + c;
      }
      if (n > 255) return false;
      parts++; start = i + 1;
    }
  }
  return parts === 4;
}

function ip(value) {
  if (value.length > 45 || value.length === 0) return false;
  if (!value.includes(':')) return ipv4(value);
  if (value.includes(':::')) return false;
  const double = value.indexOf('::');
  if (double >= 0 && value.indexOf('::', double + 2) >= 0) return false;
  const parts = value.split(':');
  let count = 0;
  for (let i = 0; i < parts.length; i++) {
    const part = parts[i];
    if (part === '') {
      if (double < 0 || i === 0 && !value.startsWith('::') || i === parts.length - 1 && !value.endsWith('::')) return false;
      continue;
    }
    if (part.includes('.')) {
      if (i !== parts.length - 1 || !ipv4(part)) return false;
      count += 2;
    } else {
      if (part.length > 4) return false;
      for (let j = 0; j < part.length; j++) if (!hex(part.charCodeAt(j))) return false;
      count++;
    }
  }
  return double >= 0 ? count < 8 : count === 8;
}

function hex(c) { return c >= 48 && c <= 57 || c >= 65 && c <= 70 || c >= 97 && c <= 102; }
function converted(value, format, work) {
  switch (format) {
    case 'integer': return decimal(value, false);
    case 'port': return decimal(value, true);
    case 'boolean': return bool(value);
    case 'hostname': return hostname(value) ? value : null;
    case 'email': return email(value) ? value : null;
    case 'ip': return ip(value) ? value : null;
    case 'url': return url(value, work) ? value : null;
    default: return value;
  }
}
