'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { BUILTINS, PRIMITIVE_DOCUMENTATION, scanDocument, tokenize } = require('./language-service');

test('scans imports and top-level Argent declarations from incomplete bodies', () => {
  const source = `
import "./types.ag";
import actor Player from "./player.ag";

const byte[32] ZERO = 0x00;
state PlayerState {
  int score;
}
actor enum PlayerKind { Player; }
actor League owns PlayerState {
  entry join(pubkey owner) emits one League {
    // The body is intentionally unfinished.
  }
}
fn player_ref(byte[32] owner, int id) -> byte[32] {
  return blake2b(owner
app Stones {
  actor League;
}
`;

  const scan = scanDocument(source);
  assert.deepEqual(
    scan.imports.map(({ kind, name, path }) => ({ kind, name, path })),
    [
      { kind: 'module', name: undefined, path: './types.ag' },
      { kind: 'actor', name: 'Player', path: './player.ag' },
    ],
  );
  assert.equal(source.slice(scan.imports[0].pathStart, scan.imports[0].pathEnd), './types.ag');
  assert.equal(source.slice(scan.imports[1].pathStart, scan.imports[1].pathEnd), './player.ag');
  assert.deepEqual(
    scan.declarations.map(({ kind, name }) => ({ kind, name })),
    [
      { kind: 'constant', name: 'ZERO' },
      { kind: 'state', name: 'PlayerState' },
      { kind: 'actorEnum', name: 'PlayerKind' },
      { kind: 'actor', name: 'League' },
      { kind: 'function', name: 'player_ref' },
    ],
  );
  assert.deepEqual(scan.declarations.at(-1).params, ['owner', 'id']);
  assert.deepEqual(
    scan.declarations.at(-1).parameters.map(({ name, type }) => ({ name, type })),
    [
      { name: 'owner', type: 'byte[32]' },
      { name: 'id', type: 'int' },
    ],
  );
  assert.equal(scan.declarations.at(-1).parameters[0].signature, 'byte[32] owner');
  assert.ok(scan.declarations.at(-1).bodyStart < source.lastIndexOf('owner'));
  assert.equal(scan.declarations.at(-1).bodyEnd, source.length);
});

test('ignores declaration-shaped text in comments and strings', () => {
  const source = `
// state CommentState {}
/* actor CommentActor owns Fake {} */
const string MESSAGE = "fn string_fn() -> int";
fn real() -> int {
  return 1;
}
`;

  const scan = scanDocument(source);
  assert.deepEqual(
    scan.declarations.map(({ kind, name }) => ({ kind, name })),
    [
      { kind: 'constant', name: 'MESSAGE' },
      { kind: 'function', name: 'real' },
    ],
  );
  assert.equal(tokenize(source).some((token) => token.value === 'CommentState'), false);
  assert.equal(tokenize(source).some((token) => token.value === 'string_fn'), false);
});

test('offers the Silverscript hash builtins exposed to Argent bodies', () => {
  const names = new Set(BUILTINS.map((builtin) => builtin.name));
  for (const expected of ['blake2b', 'blake2bWithKey', 'blake3', 'blake3WithKey', 'templateHash']) {
    assert.equal(names.has(expected), true, `missing ${expected}`);
  }

  const templateHash = BUILTINS.find((builtin) => builtin.name === 'templateHash');
  assert.deepEqual(templateHash.params, ['templatePrefix', 'templateSuffix']);
  assert.match(templateHash.signature, /byte\[32\]/);
});

test('offers the Silverscript query builtins except automated state-template helpers', () => {
  const names = new Set(BUILTINS.map((builtin) => builtin.name));
  const expected = [
    'OpSha256',
    'sha256',
    'OpTxSubnetId',
    'OpTxGas',
    'OpTxPayloadLen',
    'OpTxPayloadSubstr',
    'OpOutpointTxId',
    'OpOutpointIndex',
    'OpTxInputScriptSigLen',
    'OpTxInputScriptSigSubstr',
    'OpTxInputSeq',
    'OpTxInputIsCoinbase',
    'OpTxInputSpkLen',
    'OpTxInputSpkSubstr',
    'OpTxOutputSpkLen',
    'OpTxOutputSpkSubstr',
    'OpAuthOutputCount',
    'OpAuthOutputIdx',
    'OpInputCovenantId',
    'OpOutputCovenantId',
    'OpCovInputCount',
    'OpCovInputIdx',
    'OpCovOutputCount',
    'OpCovOutputIdx',
    'OpNum2Bin',
    'OpBin2Num',
    'OpChainblockSeqCommit',
    'checkSigFromStack',
    'checkSigFromStackECDSA',
    'checkSig',
    'checkMultiSig',
    'blake2b',
    'templateHash',
  ];
  const excluded = [
    'readInputState',
    'readInputStateWithTemplate',
    'validateOutputState',
    'validateOutputStateWithTemplate',
    'verifyOutputState',
    'verifyOutputStates',
  ];

  for (const name of expected) {
    assert.equal(names.has(name), true, `missing ${name}`);
  }
  for (const name of excluded) {
    assert.equal(names.has(name), false, `Argent automates ${name}`);
  }
  assert.equal(BUILTINS.length, names.size, 'builtin names must be unique');
});

test('attaches adjacent line and block documentation to declarations', () => {
  const source = `
/// Persistent player data.
///
/// Used by **Player** actors.
state PlayerState {
  int score;
}

/**
 * Produces a stable player identifier.
 *
 * The result is always 32 bytes.
 */
fn playerId(pubkey owner) -> byte[32] {
  return blake2b(owner);
}

// Ordinary comments are not declaration documentation.
actor Player owns PlayerState {}
`;

  const scan = scanDocument(source);
  const state = scan.declarations.find((item) => item.name === 'PlayerState');
  const fn = scan.declarations.find((item) => item.name === 'playerId');
  const actor = scan.declarations.find((item) => item.name === 'Player');

  assert.equal(state.documentation, 'Persistent player data.\n\nUsed by **Player** actors.');
  assert.equal(fn.documentation, 'Produces a stable player identifier.\n\nThe result is always 32 bytes.');
  assert.equal(actor.documentation, undefined);
});

test('indexes owned-state fields and actor source ranges for self-member resolution', () => {
  const source = `
state PairCapsule {
  /// Covenant id of the quote asset.
  covid quote_id;
  actor_type<AssetCapsule> quote_type;
}

state PairState expands PairCapsule {
  reserve: ReserveState;
}

actor Pair owns PairState {
  entry swap() emits none {
    require(self.quote_id.co_spent());
  }
}
`;

  const scan = scanDocument(source);
  const capsule = scan.declarations.find((item) => item.name === 'PairCapsule');
  const state = scan.declarations.find((item) => item.name === 'PairState');
  const actor = scan.declarations.find((item) => item.name === 'Pair');
  const quoteId = capsule.fields.find((field) => field.name === 'quote_id');

  assert.equal(quoteId.type, 'covid');
  assert.equal(quoteId.documentation, 'Covenant id of the quote asset.');
  assert.equal(capsule.fields.find((field) => field.name === 'quote_type').type, 'actor_type<AssetCapsule>');
  assert.equal(state.baseState, 'PairCapsule');
  assert.equal(state.fields.find((field) => field.name === 'reserve').type, 'ReserveState');
  assert.equal(actor.ownedState, 'PairState');
  assert.ok(actor.bodyStart < source.indexOf('self.quote_id'));
  assert.ok(actor.bodyEnd > source.indexOf('self.quote_id'));
});

test('indexes entry and delegate callables with parameters and implementation body ranges', () => {
  const source = `
state PairState {
  int reserve;
}

actor Pair owns PairState {
  /// Exchanges one side of the pair.
  entry swap(int amount, covid asset_id)
  observes asset by asset_id {
    inputs {
      payment: Pair;
    }
  }
  emits none {
    require(amount > 0);
  }

  delegate authorize(sig owner_sig) consumes {
    controller: Pair;
  } {
    require(checkSig(owner_sig, controller.owner));
  }
}
`;

  const scan = scanDocument(source);
  const actor = scan.declarations.find((item) => item.name === 'Pair');
  assert.deepEqual(
    actor.members.map(({ kind, name, params }) => ({ kind, name, params })),
    [
      { kind: 'entry', name: 'swap', params: ['amount', 'asset_id'] },
      { kind: 'delegate', name: 'authorize', params: ['owner_sig'] },
    ],
  );

  const swap = actor.members[0];
  assert.equal(swap.documentation, 'Exchanges one side of the pair.');
  assert.deepEqual(
    swap.parameters.map(({ name, type }) => ({ name, type })),
    [
      { name: 'amount', type: 'int' },
      { name: 'asset_id', type: 'covid' },
    ],
  );
  assert.ok(swap.bodyStart < source.indexOf('require(amount'));
  assert.ok(swap.bodyEnd > source.indexOf('require(amount'));
  assert.ok(swap.bodyStart > source.indexOf('inputs {'));

  const authorize = actor.members[1];
  assert.deepEqual(
    authorize.parameters.map(({ name, type }) => ({ name, type })),
    [{ name: 'owner_sig', type: 'sig' }],
  );
  assert.ok(authorize.bodyStart < source.indexOf('checkSig(owner_sig'));
  assert.ok(authorize.bodyEnd > source.indexOf('checkSig(owner_sig'));
});

test('documents Argent-specific identity and actor-handle types', () => {
  assert.match(PRIMITIVE_DOCUMENTATION.covid, /^A 32-byte handle identifying a covenant instance/);
  assert.match(PRIMITIVE_DOCUMENTATION.covid, /target of an `observes` clause/);
  assert.match(PRIMITIVE_DOCUMENTATION.covid, /co_spent/);
  assert.match(PRIMITIVE_DOCUMENTATION.actor_type, /runtime-selected actor implementation/);
  assert.match(PRIMITIVE_DOCUMENTATION.actor_type, /not an actor instance/);
});
