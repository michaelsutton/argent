'use strict';

const KEYWORDS = Object.freeze([
  'actor',
  'app',
  'as',
  'become',
  'by',
  'consumes',
  'const',
  'delegate',
  'else',
  'emits',
  'entry',
  'enum',
  'expands',
  'false',
  'fn',
  'from',
  'if',
  'import',
  'inputs',
  'leader',
  'none',
  'observes',
  'one',
  'outputs',
  'owns',
  'return',
  'self',
  'spawns',
  'state',
  'true',
  'virtual',
]);

const PRIMITIVE_TYPES = Object.freeze([
  'actor_type',
  'bool',
  'byte',
  'bytes',
  'covid',
  'datasig',
  'int',
  'pubkey',
  'sig',
  'string',
]);

const PRIMITIVE_DOCUMENTATION = Object.freeze({
  covid:
    'A 32-byte handle identifying a covenant instance; use it as the target of an `observes` clause or call `.co_spent()` to require that covenant as a valid input in the current transaction.',
  actor_type:
    'A first-class handle to a runtime-selected actor implementation compatible with `State`; it identifies the implementation/template, not an actor instance.',
});

const BUILTINS = Object.freeze([
  { name: 'blake2b', signature: 'blake2b(data: byte[]) -> byte[32]', params: ['data'] },
  {
    name: 'blake2bWithKey',
    signature: 'blake2bWithKey(data: byte[], key: byte[]) -> byte[32]',
    params: ['data', 'key'],
  },
  { name: 'blake3', signature: 'blake3(data: byte[]) -> byte[32]', params: ['data'] },
  {
    name: 'blake3WithKey',
    signature: 'blake3WithKey(data: byte[], key: byte[32]) -> byte[32]',
    params: ['data', 'key'],
  },
  { name: 'sha256', signature: 'sha256(data: byte[]) -> byte[32]', params: ['data'] },
  {
    name: 'checkSig',
    signature: 'checkSig(signature: sig, public_key: pubkey) -> bool',
    params: ['signature', 'public_key'],
  },
  {
    name: 'checkSigFromStack',
    signature: 'checkSigFromStack(signature: datasig, digest: byte[32], publicKey: pubkey) -> bool',
    params: ['signature', 'digest', 'publicKey'],
  },
  {
    name: 'checkSigFromStackECDSA',
    signature: 'checkSigFromStackECDSA(signature: datasig, digest: byte[32], publicKey: byte[33]) -> bool',
    params: ['signature', 'digest', 'publicKey'],
  },
  {
    name: 'checkMultiSig',
    signature: 'checkMultiSig(signatures: sig[], publicKeys: pubkey[]) -> bool',
    params: ['signatures', 'publicKeys'],
  },
  { name: 'co_spent', signature: 'value.co_spent() -> bool', params: [] },
  { name: 'require', signature: 'require(condition: bool)', params: ['condition'] },
  {
    name: 'templateHash',
    signature: 'templateHash(templatePrefix: byte[], templateSuffix: byte[]) -> byte[32]',
    params: ['templatePrefix', 'templateSuffix'],
  },
  { name: 'unique', signature: 'unique(domain: string, value) -> byte[32]', params: ['domain', 'value'] },
  { name: 'OpSha256', signature: 'OpSha256(data)', params: ['data'] },
  { name: 'OpTxSubnetId', signature: 'OpTxSubnetId()', params: [] },
  { name: 'OpTxGas', signature: 'OpTxGas()', params: [] },
  { name: 'OpTxPayloadLen', signature: 'OpTxPayloadLen()', params: [] },
  { name: 'OpTxPayloadSubstr', signature: 'OpTxPayloadSubstr(start, length)', params: ['start', 'length'] },
  { name: 'OpOutpointTxId', signature: 'OpOutpointTxId(inputIndex)', params: ['inputIndex'] },
  { name: 'OpOutpointIndex', signature: 'OpOutpointIndex(inputIndex)', params: ['inputIndex'] },
  {
    name: 'OpTxInputScriptSigLen',
    signature: 'OpTxInputScriptSigLen(inputIndex)',
    params: ['inputIndex'],
  },
  {
    name: 'OpTxInputScriptSigSubstr',
    signature: 'OpTxInputScriptSigSubstr(inputIndex, start, length)',
    params: ['inputIndex', 'start', 'length'],
  },
  { name: 'OpTxInputSeq', signature: 'OpTxInputSeq(inputIndex)', params: ['inputIndex'] },
  { name: 'OpTxInputIsCoinbase', signature: 'OpTxInputIsCoinbase(inputIndex)', params: ['inputIndex'] },
  { name: 'OpTxInputSpkLen', signature: 'OpTxInputSpkLen(inputIndex)', params: ['inputIndex'] },
  {
    name: 'OpTxInputSpkSubstr',
    signature: 'OpTxInputSpkSubstr(inputIndex, start, length)',
    params: ['inputIndex', 'start', 'length'],
  },
  { name: 'OpTxOutputSpkLen', signature: 'OpTxOutputSpkLen(outputIndex)', params: ['outputIndex'] },
  {
    name: 'OpTxOutputSpkSubstr',
    signature: 'OpTxOutputSpkSubstr(outputIndex, start, length)',
    params: ['outputIndex', 'start', 'length'],
  },
  { name: 'OpAuthOutputCount', signature: 'OpAuthOutputCount(inputIndex)', params: ['inputIndex'] },
  {
    name: 'OpAuthOutputIdx',
    signature: 'OpAuthOutputIdx(inputIndex, outputOrdinal)',
    params: ['inputIndex', 'outputOrdinal'],
  },
  { name: 'OpInputCovenantId', signature: 'OpInputCovenantId(inputIndex)', params: ['inputIndex'] },
  { name: 'OpOutputCovenantId', signature: 'OpOutputCovenantId(outputIndex)', params: ['outputIndex'] },
  { name: 'OpCovInputCount', signature: 'OpCovInputCount(covenantId)', params: ['covenantId'] },
  {
    name: 'OpCovInputIdx',
    signature: 'OpCovInputIdx(covenantId, inputOrdinal)',
    params: ['covenantId', 'inputOrdinal'],
  },
  { name: 'OpCovOutputCount', signature: 'OpCovOutputCount(covenantId)', params: ['covenantId'] },
  {
    name: 'OpCovOutputIdx',
    signature: 'OpCovOutputIdx(covenantId, outputOrdinal)',
    params: ['covenantId', 'outputOrdinal'],
  },
  { name: 'OpNum2Bin', signature: 'OpNum2Bin(value, size)', params: ['value', 'size'] },
  { name: 'OpBin2Num', signature: 'OpBin2Num(data)', params: ['data'] },
  {
    name: 'OpChainblockSeqCommit',
    signature: 'OpChainblockSeqCommit(blockHash)',
    params: ['blockHash'],
  },
]);

function isIdentStart(char) {
  return /[A-Za-z_]/.test(char);
}

function isIdentContinue(char) {
  return /[A-Za-z0-9_]/.test(char);
}

/**
 * A deliberately tolerant tokenizer for editor use. It skips comments, keeps
 * string literals as one token, and accepts unfinished input.
 */
function tokenize(source) {
  const tokens = [];
  let pos = 0;

  while (pos < source.length) {
    const char = source[pos];

    if (/\s/.test(char)) {
      pos += 1;
      continue;
    }

    if (char === '/' && source[pos + 1] === '/') {
      pos += 2;
      while (pos < source.length && source[pos] !== '\n') {
        pos += 1;
      }
      continue;
    }

    if (char === '/' && source[pos + 1] === '*') {
      pos += 2;
      while (pos < source.length && !(source[pos] === '*' && source[pos + 1] === '/')) {
        pos += 1;
      }
      pos = Math.min(pos + 2, source.length);
      continue;
    }

    if (char === '"' || char === "'") {
      const quote = char;
      const start = pos;
      pos += 1;
      let value = '';
      while (pos < source.length && source[pos] !== quote) {
        if (source[pos] === '\\' && pos + 1 < source.length) {
          value += source[pos + 1];
          pos += 2;
        } else {
          value += source[pos];
          pos += 1;
        }
      }
      if (pos < source.length) {
        pos += 1;
      }
      tokens.push({ kind: 'string', value, start, end: pos });
      continue;
    }

    if (isIdentStart(char)) {
      const start = pos;
      pos += 1;
      while (pos < source.length && isIdentContinue(source[pos])) {
        pos += 1;
      }
      tokens.push({ kind: 'ident', value: source.slice(start, pos), start, end: pos });
      continue;
    }

    if (/[0-9]/.test(char)) {
      const start = pos;
      pos += 1;
      while (pos < source.length && /[A-Za-z0-9_]/.test(source[pos])) {
        pos += 1;
      }
      tokens.push({ kind: 'number', value: source.slice(start, pos), start, end: pos });
      continue;
    }

    const pair = source.slice(pos, pos + 2);
    if (pair === '->' || pair === '<-' || pair === '==' || pair === '!=' || pair === '<=' || pair === '>=') {
      tokens.push({ kind: 'symbol', value: pair, start: pos, end: pos + 2 });
      pos += 2;
      continue;
    }

    tokens.push({ kind: 'symbol', value: char, start: pos, end: pos + 1 });
    pos += 1;
  }

  return tokens;
}

function ident(token, value) {
  return token && token.kind === 'ident' && (value === undefined || token.value === value);
}

function symbol(token, value) {
  return token && token.kind === 'symbol' && token.value === value;
}

function normalizedSlice(source, start, end) {
  return source.slice(start, end).replace(/\s+/g, ' ').trim();
}

function cleanBlockDocumentation(value) {
  return value
    .split(/\r\n|\r|\n/)
    .map((line) => line.replace(/^\s*\* ?/, '').replace(/[ \t]+$/, ''))
    .join('\n')
    .replace(/^\s*\n/, '')
    .replace(/\n\s*$/, '')
    .trim();
}

function leadingDocumentation(source, declarationStart) {
  const prefix = source.slice(0, declarationStart);
  const lineStart = Math.max(prefix.lastIndexOf('\n'), prefix.lastIndexOf('\r')) + 1;
  if (prefix.slice(lineStart).trim() !== '') {
    return undefined;
  }

  const lines = prefix.slice(0, lineStart).replace(/\r\n$|\r$|\n$/, '').split(/\r\n|\r|\n/);
  const lineDocumentation = [];
  while (lines.length > 0) {
    const match = lines.at(-1).match(/^\s*\/\/\/(?: ?)(.*)$/);
    if (!match) {
      break;
    }
    lineDocumentation.unshift(match[1].replace(/[ \t]+$/, ''));
    lines.pop();
  }
  if (lineDocumentation.length > 0) {
    return lineDocumentation.join('\n').trim();
  }

  const preceding = prefix.slice(0, lineStart).replace(/\r\n$|\r$|\n$/, '');
  const close = preceding.lastIndexOf('*/');
  if (close < 0 || preceding.slice(close + 2).trim() !== '') {
    return undefined;
  }
  const open = preceding.lastIndexOf('/**', close);
  if (open < 0) {
    return undefined;
  }
  return cleanBlockDocumentation(preceding.slice(open + 3, close)) || undefined;
}

function findHeaderEnd(tokens, start, terminators) {
  for (let index = start; index < tokens.length; index += 1) {
    if (tokens[index].kind === 'symbol' && terminators.has(tokens[index].value)) {
      return tokens[index].start;
    }
  }
  return tokens.length > 0 ? tokens[tokens.length - 1].end : 0;
}

function findSymbolIndex(tokens, start, value) {
  for (let index = start; index < tokens.length; index += 1) {
    if (symbol(tokens[index], value)) {
      return index;
    }
  }
  return -1;
}

function matchingSymbolIndex(tokens, openIndex, open, close) {
  if (openIndex < 0 || !symbol(tokens[openIndex], open)) {
    return -1;
  }
  let depth = 0;
  for (let index = openIndex; index < tokens.length; index += 1) {
    if (symbol(tokens[index], open)) {
      depth += 1;
    } else if (symbol(tokens[index], close)) {
      depth -= 1;
      if (depth === 0) {
        return index;
      }
    }
  }
  return -1;
}

function matchingBraceIndex(tokens, openIndex) {
  return matchingSymbolIndex(tokens, openIndex, '{', '}');
}

function typeEnd(tokens, start) {
  if (!ident(tokens[start])) {
    return start;
  }

  let index = start + 1;
  for (const [open, close] of [
    ['<', '>'],
    ['[', ']'],
  ]) {
    if (!symbol(tokens[index], open)) {
      continue;
    }
    let depth = 0;
    while (index < tokens.length) {
      if (symbol(tokens[index], open)) {
        depth += 1;
      } else if (symbol(tokens[index], close)) {
        depth -= 1;
        if (depth === 0) {
          index += 1;
          break;
        }
      }
      index += 1;
    }
  }
  return index;
}

function functionParameters(source, tokens, nameIndex) {
  const openIndex = nameIndex + 1;
  if (!symbol(tokens[openIndex], '(')) {
    return [];
  }
  const closeIndex = matchingSymbolIndex(tokens, openIndex, '(', ')');
  const end = closeIndex >= 0 ? closeIndex : tokens.length;

  const params = [];
  let depth = 0;
  for (let index = openIndex; index < end; index += 1) {
    if (symbol(tokens[index], '(')) {
      depth += 1;
      continue;
    }
    if (symbol(tokens[index], ')')) {
      depth -= 1;
      if (depth === 0) {
        break;
      }
      continue;
    }
    if (depth === 1 && ident(tokens[index]) && symbol(tokens[index + 1], ':')) {
      const typeStart = index + 2;
      const endIndex = typeEnd(tokens, typeStart);
      if (ident(tokens[typeStart])) {
        const type = normalizedSlice(source, tokens[typeStart].start, tokens[Math.max(typeStart, endIndex - 1)].end);
        params.push({
          kind: 'parameter',
          name: tokens[index].value,
          type,
          signature: `${tokens[index].value}: ${type}`,
          start: tokens[index].start,
          end: tokens[index].end,
        });
      }
    }
  }
  return params;
}

function callableBody(source, tokens, start, segmentEnd) {
  let index = start;
  let lastOpen = -1;
  let lastClose = -1;
  while (index < segmentEnd) {
    if (symbol(tokens[index], '{')) {
      const close = matchingBraceIndex(tokens, index);
      lastOpen = index;
      lastClose = close >= 0 && close < segmentEnd ? close : -1;
      index = close >= 0 ? close + 1 : segmentEnd;
    } else {
      index += 1;
    }
  }
  return {
    bodyStart: lastOpen >= 0 ? tokens[lastOpen].end : tokens[start].end,
    bodyEnd: lastClose >= 0 ? tokens[lastClose].start : source.length,
  };
}

function actorMembers(source, tokens, openIndex, closeIndex) {
  if (openIndex < 0) {
    return [];
  }

  const end = closeIndex >= 0 ? closeIndex : tokens.length;
  const starts = [];
  let depth = 1;
  for (let index = openIndex + 1; index < end; index += 1) {
    if (depth === 1 && (ident(tokens[index], 'entry') || ident(tokens[index], 'delegate')) && ident(tokens[index + 1])) {
      starts.push(index);
    }
    if (symbol(tokens[index], '{')) {
      depth += 1;
    } else if (symbol(tokens[index], '}')) {
      depth -= 1;
    }
  }

  return starts.map((start, memberIndex) => {
    const keyword = tokens[start].value;
    const nameToken = tokens[start + 1];
    const segmentEnd = starts[memberIndex + 1] ?? end;
    const parameters = functionParameters(source, tokens, start + 1);
    const paramsOpen = start + 2;
    const paramsClose = matchingSymbolIndex(tokens, paramsOpen, '(', ')');
    const signatureEnd = paramsClose >= 0 ? tokens[paramsClose].end : nameToken.end;
    return declaration(
      keyword,
      nameToken,
      normalizedSlice(source, tokens[start].start, signatureEnd),
      leadingDocumentation(source, tokens[start].start),
      parameters.map((parameter) => parameter.name),
      {
        parameters,
        ...callableBody(source, tokens, paramsClose >= 0 ? paramsClose + 1 : start + 2, segmentEnd),
      },
    );
  });
}

function stateFields(source, tokens, openIndex, closeIndex) {
  if (openIndex < 0) {
    return [];
  }

  const fields = [];
  const end = closeIndex >= 0 ? closeIndex : tokens.length;
  let index = openIndex + 1;
  while (index < end) {
    if (symbol(tokens[index], ';')) {
      index += 1;
      continue;
    }

    let nameToken;
    let type;
    let signature;
    if (ident(tokens[index], 'virtual') && ident(tokens[index + 1])) {
      nameToken = tokens[index + 1];
      type = 'byte[32]';
      signature = `virtual ${nameToken.value}`;
    } else if (ident(tokens[index]) && symbol(tokens[index + 1], ':') && ident(tokens[index + 2])) {
      nameToken = tokens[index];
      const endIndex = typeEnd(tokens, index + 2);
      type = normalizedSlice(source, tokens[index + 2].start, tokens[Math.max(index + 2, endIndex - 1)].end);
      signature = `${type} ${nameToken.value}`;
    } else if (ident(tokens[index])) {
      const nameIndex = typeEnd(tokens, index);
      if (ident(tokens[nameIndex])) {
        nameToken = tokens[nameIndex];
        type = normalizedSlice(source, tokens[index].start, nameToken.start);
        signature = `${type} ${nameToken.value}`;
      }
    }

    if (nameToken) {
      fields.push({
        kind: 'field',
        name: nameToken.value,
        type,
        signature,
        documentation: leadingDocumentation(source, tokens[index].start),
        start: nameToken.start,
        end: nameToken.end,
      });
    }

    while (index < end && !symbol(tokens[index], ';')) {
      index += 1;
    }
    index += 1;
  }
  return fields;
}

function declaration(kind, nameToken, signature, documentation, params = [], extra = {}) {
  return {
    kind,
    name: nameToken.value,
    start: nameToken.start,
    end: nameToken.end,
    signature,
    documentation,
    params,
    ...extra,
  };
}

/**
 * Extracts stable declarations, actor callables, and callable parameters
 * without parsing expressions. This keeps half-written bodies indexable.
 */
function scanDocument(source) {
  const tokens = tokenize(source);
  const imports = [];
  const declarations = [];
  let braceDepth = 0;

  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens[index];

    if (braceDepth === 0 && ident(token, 'import')) {
      if (
        ident(tokens[index + 1], 'actor') &&
        ident(tokens[index + 2]) &&
        ident(tokens[index + 3], 'from') &&
        tokens[index + 4]?.kind === 'string'
      ) {
        imports.push({
          kind: 'actor',
          name: tokens[index + 2].value,
          path: tokens[index + 4].value,
          start: tokens[index + 2].start,
          end: tokens[index + 2].end,
          pathStart: tokens[index + 4].start + 1,
          pathEnd: tokens[index + 4].end - 1,
        });
        index += 4;
      } else if (tokens[index + 1]?.kind === 'string') {
        imports.push({
          kind: 'module',
          path: tokens[index + 1].value,
          start: tokens[index + 1].start,
          end: tokens[index + 1].end,
          pathStart: tokens[index + 1].start + 1,
          pathEnd: tokens[index + 1].end - 1,
        });
        index += 1;
      }
    } else if (braceDepth === 0 && ident(token, 'state') && ident(tokens[index + 1])) {
      const name = tokens[index + 1];
      const openIndex = findSymbolIndex(tokens, index + 2, '{');
      const closeIndex = matchingBraceIndex(tokens, openIndex);
      const end = openIndex >= 0 ? tokens[openIndex].start : findHeaderEnd(tokens, index, new Set(['{']));
      const baseState =
        ident(tokens[index + 2], 'expands') && ident(tokens[index + 3]) ? tokens[index + 3].value : undefined;
      declarations.push(
        declaration(
          'state',
          name,
          normalizedSlice(source, token.start, end),
          leadingDocumentation(source, token.start),
          [],
          {
            baseState,
            fields: stateFields(source, tokens, openIndex, closeIndex),
          },
        ),
      );
    } else if (braceDepth === 0 && ident(token, 'actor')) {
      if (ident(tokens[index + 1], 'enum') && ident(tokens[index + 2])) {
        const name = tokens[index + 2];
        const end = findHeaderEnd(tokens, index, new Set(['{']));
        declarations.push(
          declaration('actorEnum', name, normalizedSlice(source, token.start, end), leadingDocumentation(source, token.start)),
        );
      } else if (ident(tokens[index + 1])) {
        const name = tokens[index + 1];
        const openIndex = findSymbolIndex(tokens, index + 2, '{');
        const closeIndex = matchingBraceIndex(tokens, openIndex);
        const end = openIndex >= 0 ? tokens[openIndex].start : findHeaderEnd(tokens, index, new Set(['{']));
        const ownedState =
          ident(tokens[index + 2], 'owns') && ident(tokens[index + 3]) ? tokens[index + 3].value : undefined;
        declarations.push(
          declaration(
            'actor',
            name,
            normalizedSlice(source, token.start, end),
            leadingDocumentation(source, token.start),
            [],
            {
              ownedState,
              bodyStart: openIndex >= 0 ? tokens[openIndex].end : name.end,
              bodyEnd: closeIndex >= 0 ? tokens[closeIndex].start : source.length,
              members: actorMembers(source, tokens, openIndex, closeIndex),
            },
          ),
        );
      }
    } else if (braceDepth === 0 && ident(token, 'fn') && ident(tokens[index + 1])) {
      const name = tokens[index + 1];
      const parameters = functionParameters(source, tokens, index + 1);
      const openIndex = findSymbolIndex(tokens, index + 2, '{');
      const closeIndex = matchingBraceIndex(tokens, openIndex);
      const end = openIndex >= 0 ? tokens[openIndex].start : findHeaderEnd(tokens, index, new Set(['{', ';']));
      declarations.push(
        declaration(
          'function',
          name,
          normalizedSlice(source, token.start, end),
          leadingDocumentation(source, token.start),
          parameters.map((parameter) => parameter.name),
          {
            parameters,
            bodyStart: openIndex >= 0 ? tokens[openIndex].end : name.end,
            bodyEnd: closeIndex >= 0 ? tokens[closeIndex].start : source.length,
          },
        ),
      );
    } else if (braceDepth === 0 && ident(token, 'const')) {
      const nameIndex = typeEnd(tokens, index + 1);
      if (ident(tokens[nameIndex])) {
        const name = tokens[nameIndex];
        const end = findHeaderEnd(tokens, index, new Set(['=', ';']));
        declarations.push(
          declaration('constant', name, normalizedSlice(source, token.start, end), leadingDocumentation(source, token.start)),
        );
      }
    } else if (braceDepth === 0 && ident(token, 'app') && ident(tokens[index + 1])) {
      const name = tokens[index + 1];
      const end = findHeaderEnd(tokens, index, new Set(['{']));
      declarations.push(
        declaration('app', name, normalizedSlice(source, token.start, end), leadingDocumentation(source, token.start)),
      );
    }

    if (symbol(token, '{')) {
      braceDepth += 1;
    } else if (symbol(token, '}')) {
      braceDepth = Math.max(0, braceDepth - 1);
    }
  }

  return { source, tokens, imports, declarations };
}

module.exports = {
  BUILTINS,
  KEYWORDS,
  PRIMITIVE_DOCUMENTATION,
  PRIMITIVE_TYPES,
  scanDocument,
  tokenize,
};
