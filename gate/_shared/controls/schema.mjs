export const SCHEMA_VERSION = 1;
export const SOURCE_KINDS = Object.freeze(['midi', 'keyboard', 'gamepad', 'pointer', 'motion', 'wifisense', 'spine']);
export const MODES = Object.freeze(['absolute', 'relative', 'toggle', 'momentary', 'trigger']);
export const CURVES = Object.freeze(['linear', 'log', 'exp', 's']);
export const MAP_FIELDS = Object.freeze(['source', 'control', 'target', 'mode', 'range', 'curve', 'invert', 'smoothing', 'deadzone', 'comment']);
export const DOC_FIELDS = Object.freeze(['v', 'surface', 'maps']);
export const MAX_MAPS = 512;
export const MAX_COMMENT = 280;
export const MAX_DEADZONE = 0.5;

export const SURFACE_RE = /^[a-z0-9][a-z0-9._/-]{0,79}$/;
export const CONTROL_RE = /^[\x21-\x7e]{1,120}$/;
export const TARGET_RE = /^[A-Za-z0-9._:/-]{1,120}$/;

export const MAP_DEFAULTS = Object.freeze({
  mode: 'absolute',
  range: Object.freeze([0, 1]),
  curve: 'linear',
  invert: false,
  smoothing: 0,
  deadzone: 0,
  comment: '',
});

export const REASONS = Object.freeze({
  json: 'the file is not valid JSON',
  doc: 'the mapping file must be a JSON object',
  v: `v must be ${SCHEMA_VERSION}, the only mapping schema version`,
  surface: 'surface must be 1 to 80 characters: lowercase letters, digits, dot, dash, underscore or slash, starting with a letter or digit',
  maps: 'maps must be a list',
  tooMany: `a surface holds at most ${MAX_MAPS} maps`,
  map: 'each map must be an object',
  unknown: 'this field is not part of the mapping schema',
  missing: 'this field is required',
  source: `source must be one of ${SOURCE_KINDS.join(', ')}`,
  control: 'control must be 1 to 120 visible characters with no spaces',
  target: 'target must be 1 to 120 characters: letters, digits, dot, dash, underscore, colon or slash',
  mode: `mode must be one of ${MODES.join(', ')}`,
  range: 'range must be two finite numbers, low then high, with low below high',
  curve: `curve must be one of ${CURVES.join(', ')}`,
  invert: 'invert must be true or false',
  smoothing: 'smoothing must be a number from 0 up to, not including, 1',
  deadzone: `deadzone must be a number from 0 to ${MAX_DEADZONE}`,
  comment: `comment must be text of at most ${MAX_COMMENT} characters`,
  duplicate: 'the same input is already mapped to this target',
});

const isObject = (x) => x !== null && typeof x === 'object' && !Array.isArray(x);
const fail = (errors, path, code) => { errors.push({ path, code, reason: REASONS[code] }); };

const FIELD_CHECKS = {
  source: (x) => SOURCE_KINDS.includes(x),
  control: (x) => typeof x === 'string' && CONTROL_RE.test(x),
  target: (x) => typeof x === 'string' && TARGET_RE.test(x),
  mode: (x) => MODES.includes(x),
  range: (x) => Array.isArray(x) && x.length === 2 && Number.isFinite(x[0]) && Number.isFinite(x[1]) && x[0] < x[1],
  curve: (x) => CURVES.includes(x),
  invert: (x) => x === true || x === false,
  smoothing: (x) => Number.isFinite(x) && x >= 0 && x < 1,
  deadzone: (x) => Number.isFinite(x) && x >= 0 && x <= MAX_DEADZONE,
  comment: (x) => typeof x === 'string' && x.length <= MAX_COMMENT,
};

export function validateMap(map, path = 'map') {
  const errors = [];
  if (!isObject(map)) { fail(errors, path, 'map'); return errors; }
  for (const key of Object.keys(map)) if (!MAP_FIELDS.includes(key)) fail(errors, `${path}.${key}`, 'unknown');
  for (const field of MAP_FIELDS) {
    if (!(field in map)) { fail(errors, `${path}.${field}`, 'missing'); continue; }
    if (!FIELD_CHECKS[field](map[field])) fail(errors, `${path}.${field}`, field);
  }
  return errors;
}

export function validate(doc) {
  const errors = [];
  if (!isObject(doc)) { fail(errors, '', 'doc'); return { ok: false, errors }; }
  for (const key of Object.keys(doc)) if (!DOC_FIELDS.includes(key)) fail(errors, key, 'unknown');
  if (!('v' in doc)) fail(errors, 'v', 'missing');
  else if (doc.v !== SCHEMA_VERSION) fail(errors, 'v', 'v');
  if (!('surface' in doc)) fail(errors, 'surface', 'missing');
  else if (typeof doc.surface !== 'string' || !SURFACE_RE.test(doc.surface)) fail(errors, 'surface', 'surface');
  if (!('maps' in doc)) fail(errors, 'maps', 'missing');
  else if (!Array.isArray(doc.maps)) fail(errors, 'maps', 'maps');
  else {
    if (doc.maps.length > MAX_MAPS) fail(errors, 'maps', 'tooMany');
    const seen = new Set();
    doc.maps.forEach((map, i) => {
      const mapErrors = validateMap(map, `maps[${i}]`);
      errors.push(...mapErrors);
      if (mapErrors.length) return;
      const key = `${map.source}\u0000${map.control}\u0000${map.target}`;
      if (seen.has(key)) fail(errors, `maps[${i}]`, 'duplicate');
      seen.add(key);
    });
  }
  return { ok: errors.length === 0, errors };
}

export function normalizeMap(partial = {}) {
  const out = {};
  for (const field of MAP_FIELDS) {
    if (field in partial) out[field] = field === 'range' && Array.isArray(partial.range) ? [partial.range[0], partial.range[1]] : partial[field];
    else if (field in MAP_DEFAULTS) out[field] = field === 'range' ? [MAP_DEFAULTS.range[0], MAP_DEFAULTS.range[1]] : MAP_DEFAULTS[field];
  }
  for (const key of Object.keys(partial)) if (!MAP_FIELDS.includes(key)) out[key] = partial[key];
  return out;
}

function orderedMap(map) {
  const out = {};
  for (const field of MAP_FIELDS) out[field] = field === 'range' ? [map.range[0], map.range[1]] : map[field];
  return out;
}

export function serialize(doc) {
  const { ok, errors } = validate(doc);
  if (!ok) throw new TypeError(`mapping file refused: ${errors.map((e) => `${e.path || '(file)'} ${e.reason}`).join('; ')}`);
  const head = `{\n  "v": ${JSON.stringify(doc.v)},\n  "surface": ${JSON.stringify(doc.surface)},\n  "maps": [`;
  if (!doc.maps.length) return `${head}]\n}\n`;
  const rows = doc.maps.map((m) => `    ${JSON.stringify(orderedMap(m))}`).join(',\n');
  return `${head}\n${rows}\n  ]\n}\n`;
}

export function parse(text) {
  let doc;
  try { doc = JSON.parse(String(text)); } catch { return { ok: false, doc: null, errors: [{ path: '', code: 'json', reason: REASONS.json }] }; }
  const { ok, errors } = validate(doc);
  return { ok, doc: ok ? doc : null, errors };
}
