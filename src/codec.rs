use std::{collections::BTreeMap, fmt};

use serde::{Deserialize, Serialize};

use crate::artifact::{
    FieldArtifact, RuntimeStateArtifact, SilAbiArtifact, SilActorArtifact, SilEntryArtifact, StateArtifact, TypeArtifact,
};

const OP_0: u8 = 0x00;
const OP_DATA_1: u8 = 0x01;
const OP_DATA_75: u8 = 0x4b;
const OP_PUSH_DATA_1: u8 = 0x4c;
const OP_PUSH_DATA_2: u8 = 0x4d;
const OP_PUSH_DATA_4: u8 = 0x4e;
const OP_1_NEGATE: u8 = 0x4f;
const OP_1: u8 = 0x51;
const OP_16: u8 = 0x60;
const OP_1_NEGATE_VALUE: u8 = 0x81;

pub type CodecResult<T> = std::result::Result<T, CodecError>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum ArtifactValue {
    Int(i64),
    Bool(bool),
    Byte(u8),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<ArtifactValue>),
    Object(BTreeMap<String, ArtifactValue>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodecError {
    UnknownActor(String),
    UnknownEntry { actor: String, entry: String },
    UnknownStruct(String),
    WrongArgumentCount { entry: String, expected: usize, actual: usize },
    MissingField(String),
    UnknownField(String),
    DuplicateField(String),
    TypeMismatch { expected: String, actual: String },
    UnsupportedType(String),
    InvalidLength { name: String, expected: usize, actual: usize },
    InvalidNumber { value: i64, size: usize },
    InvalidHex(String),
    InvalidPush(String),
    TrailingStateBytes { offset: usize, len: usize },
}

impl fmt::Display for CodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownActor(actor) => write!(f, "unknown actor `{actor}`"),
            Self::UnknownEntry { actor, entry } => write!(f, "unknown entry `{actor}::{entry}`"),
            Self::UnknownStruct(name) => write!(f, "unknown struct `{name}`"),
            Self::WrongArgumentCount { entry, expected, actual } => {
                write!(f, "entry `{entry}` expects {expected} arguments, got {actual}")
            }
            Self::MissingField(field) => write!(f, "missing field `{field}`"),
            Self::UnknownField(field) => write!(f, "unknown field `{field}`"),
            Self::DuplicateField(field) => write!(f, "duplicate field `{field}`"),
            Self::TypeMismatch { expected, actual } => write!(f, "expected {expected}, got {actual}"),
            Self::UnsupportedType(ty) => write!(f, "unsupported artifact type `{ty}`"),
            Self::InvalidLength { name, expected, actual } => {
                write!(f, "`{name}` expects {expected} bytes, got {actual}")
            }
            Self::InvalidNumber { value, size } => write!(f, "number {value} does not fit in {size} bytes"),
            Self::InvalidHex(message) => write!(f, "invalid hex: {message}"),
            Self::InvalidPush(message) => write!(f, "invalid push-only script: {message}"),
            Self::TrailingStateBytes { offset, len } => {
                write!(f, "state script has {len} trailing bytes at offset {offset}")
            }
        }
    }
}

impl std::error::Error for CodecError {}

pub fn encode_actor_entry_sig_script(
    abi: &SilAbiArtifact,
    actor_name: &str,
    entry_name: &str,
    args: &[ArtifactValue],
) -> CodecResult<Vec<u8>> {
    let actor =
        abi.actors.iter().find(|actor| actor.name == actor_name).ok_or_else(|| CodecError::UnknownActor(actor_name.to_string()))?;
    let entry = actor
        .entries
        .iter()
        .find(|entry| entry.name == entry_name)
        .ok_or_else(|| CodecError::UnknownEntry { actor: actor_name.to_string(), entry: entry_name.to_string() })?;
    encode_entry_sig_script(abi, actor, entry, args)
}

pub fn encode_entry_sig_script(
    abi: &SilAbiArtifact,
    actor: &SilActorArtifact,
    entry: &SilEntryArtifact,
    args: &[ArtifactValue],
) -> CodecResult<Vec<u8>> {
    let params = entry_params(entry);
    if params.len() != args.len() {
        return Err(CodecError::WrongArgumentCount {
            entry: format!("{}::{}", actor.name, entry.name),
            expected: params.len(),
            actual: args.len(),
        });
    }

    let ctx = TypeContext::new(abi);
    let mut out = Vec::new();
    for ((name, ty), value) in params.iter().zip(args) {
        push_sig_arg(&mut out, &ctx, name, ty, value)?;
    }
    if let Some(selector) = entry.selector {
        push_i64(&mut out, selector)?;
    }
    Ok(out)
}

pub fn encode_runtime_state_script(
    runtime_state: &RuntimeStateArtifact,
    values: &BTreeMap<String, ArtifactValue>,
) -> CodecResult<Vec<u8>> {
    for name in values.keys() {
        if runtime_state.fields.iter().all(|field| &field.name != name) {
            return Err(CodecError::UnknownField(name.clone()));
        }
    }

    let mut out = Vec::new();
    for field in &runtime_state.fields {
        let value = values.get(&field.name).ok_or_else(|| CodecError::MissingField(field.name.clone()))?;
        let payload = encode_state_payload(&field.name, &field.ty, value)?;
        push_data_explicit(&mut out, &payload);
    }
    Ok(out)
}

pub fn decode_runtime_state_script(
    runtime_state: &RuntimeStateArtifact,
    state_script: &[u8],
) -> CodecResult<BTreeMap<String, ArtifactValue>> {
    let pushes = parse_pushes(state_script)?;
    if pushes.len() < runtime_state.fields.len() {
        return Err(CodecError::InvalidPush(format!("expected {} state pushes, got {}", runtime_state.fields.len(), pushes.len())));
    }
    if pushes.len() > runtime_state.fields.len() {
        let offset = pushes[runtime_state.fields.len()].0;
        return Err(CodecError::TrailingStateBytes { offset, len: state_script.len() - offset });
    }

    let mut values = BTreeMap::new();
    for (field, (_, payload)) in runtime_state.fields.iter().zip(pushes) {
        values.insert(field.name.clone(), decode_state_payload(&field.name, &field.ty, &payload)?);
    }
    Ok(values)
}

pub fn decode_hex(hex: &str) -> CodecResult<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        return Err(CodecError::InvalidHex("odd length".to_string()));
    }
    hex.as_bytes().chunks_exact(2).map(|chunk| Ok((hex_nibble(chunk[0])? << 4) | hex_nibble(chunk[1])?)).collect()
}

pub fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn entry_params(entry: &SilEntryArtifact) -> Vec<(&str, &TypeArtifact)> {
    entry
        .user_params
        .iter()
        .map(|param| (param.name.as_str(), &param.ty))
        .chain(entry.hidden_params.iter().map(|param| (param.name.as_str(), &param.ty)))
        .collect()
}

struct TypeContext<'a> {
    states: BTreeMap<&'a str, &'a StateArtifact>,
}

impl<'a> TypeContext<'a> {
    fn new(abi: &'a SilAbiArtifact) -> Self {
        Self { states: abi.states.iter().map(|state| (state.name.as_str(), state)).collect() }
    }

    fn state(&self, name: &str) -> CodecResult<&'a StateArtifact> {
        self.states.get(name).copied().ok_or_else(|| CodecError::UnknownStruct(name.to_string()))
    }
}

fn push_sig_arg(out: &mut Vec<u8>, ctx: &TypeContext<'_>, name: &str, ty: &TypeArtifact, value: &ArtifactValue) -> CodecResult<()> {
    match ty {
        TypeArtifact::Struct { name: struct_name } => {
            let fields = object_fields(value)?;
            push_struct_fields(out, ctx, ctx.state(struct_name)?, fields)
        }
        TypeArtifact::FixedArray { item, len } if matches!(item.as_ref(), TypeArtifact::Struct { .. }) => {
            push_struct_array_fields(out, ctx, item, Some(*len), value)
        }
        TypeArtifact::DynamicArray { item } if matches!(item.as_ref(), TypeArtifact::Struct { .. }) => {
            push_struct_array_fields(out, ctx, item, None, value)
        }
        TypeArtifact::Int => push_i64(out, expect_int(value)?),
        TypeArtifact::Bool => push_i64(out, i64::from(expect_bool(value)?)),
        TypeArtifact::Byte => {
            push_data_canonical(out, &[expect_byte(value)?]);
            Ok(())
        }
        TypeArtifact::Bytes => {
            push_data_canonical(out, expect_bytes(value)?);
            Ok(())
        }
        TypeArtifact::Text => {
            push_data_canonical(out, expect_text(value)?.as_bytes());
            Ok(())
        }
        TypeArtifact::Pubkey => push_fixed_bytes(out, name, value, 32),
        TypeArtifact::Sig => push_fixed_bytes(out, name, value, 65),
        TypeArtifact::Datasig => push_fixed_bytes(out, name, value, 64),
        TypeArtifact::FixedBytes { len } => push_fixed_bytes(out, name, value, *len),
        TypeArtifact::FixedArray { item, len } => {
            let payload = encode_array_payload(name, item, Some(*len), value)?;
            push_data_canonical(out, &payload);
            Ok(())
        }
        TypeArtifact::DynamicArray { item } => {
            let payload = encode_array_payload(name, item, None, value)?;
            push_data_canonical(out, &payload);
            Ok(())
        }
    }
}

fn push_struct_fields(
    out: &mut Vec<u8>,
    ctx: &TypeContext<'_>,
    state: &StateArtifact,
    fields: &BTreeMap<String, ArtifactValue>,
) -> CodecResult<()> {
    assert_no_extra_fields(fields, &state.fields)?;
    for field in &state.fields {
        let value = fields.get(&field.name).ok_or_else(|| CodecError::MissingField(field.name.clone()))?;
        push_sig_arg(out, ctx, &field.name, &field.ty, value)?;
    }
    Ok(())
}

fn push_struct_array_fields(
    out: &mut Vec<u8>,
    ctx: &TypeContext<'_>,
    item: &TypeArtifact,
    expected_len: Option<usize>,
    value: &ArtifactValue,
) -> CodecResult<()> {
    let TypeArtifact::Struct { name } = item else {
        return Err(CodecError::UnsupportedType(type_name(item)));
    };
    let state = ctx.state(name)?;
    let values = expect_array(value)?;
    if let Some(expected) = expected_len {
        require_len(name, expected, values.len())?;
    }

    let mut object_values = Vec::with_capacity(values.len());
    for value in values {
        let fields = object_fields(value)?;
        assert_no_extra_fields(fields, &state.fields)?;
        object_values.push(fields);
    }

    for field in &state.fields {
        let mut field_values = Vec::with_capacity(object_values.len());
        for object in &object_values {
            field_values.push(object.get(&field.name).ok_or_else(|| CodecError::MissingField(field.name.clone()))?.clone());
        }
        push_sig_arg(
            out,
            ctx,
            &field.name,
            &TypeArtifact::DynamicArray { item: Box::new(field.ty.clone()) },
            &ArtifactValue::Array(field_values),
        )?;
    }
    Ok(())
}

fn encode_state_payload(name: &str, ty: &TypeArtifact, value: &ArtifactValue) -> CodecResult<Vec<u8>> {
    match ty {
        TypeArtifact::Bytes => Ok(expect_bytes(value)?.to_vec()),
        TypeArtifact::Text => Ok(expect_text(value)?.as_bytes().to_vec()),
        TypeArtifact::DynamicArray { item } => encode_array_payload(name, item, None, value),
        _ => encode_fixed_payload(name, ty, value),
    }
}

fn decode_state_payload(name: &str, ty: &TypeArtifact, payload: &[u8]) -> CodecResult<ArtifactValue> {
    match ty {
        TypeArtifact::Int => {
            require_len(name, 8, payload.len())?;
            Ok(ArtifactValue::Int(deserialize_i64(payload)?))
        }
        TypeArtifact::Bool => {
            require_len(name, 1, payload.len())?;
            match payload[0] {
                0 => Ok(ArtifactValue::Bool(false)),
                1 => Ok(ArtifactValue::Bool(true)),
                value => Err(CodecError::TypeMismatch { expected: "bool byte 0 or 1".to_string(), actual: value.to_string() }),
            }
        }
        TypeArtifact::Byte => {
            require_len(name, 1, payload.len())?;
            Ok(ArtifactValue::Byte(payload[0]))
        }
        TypeArtifact::Bytes => Ok(ArtifactValue::Bytes(payload.to_vec())),
        TypeArtifact::Text => String::from_utf8(payload.to_vec())
            .map(ArtifactValue::Text)
            .map_err(|err| CodecError::TypeMismatch { expected: "utf-8 string".to_string(), actual: err.to_string() }),
        TypeArtifact::Pubkey => decode_fixed_bytes(name, payload, 32),
        TypeArtifact::Sig => decode_fixed_bytes(name, payload, 65),
        TypeArtifact::Datasig => decode_fixed_bytes(name, payload, 64),
        TypeArtifact::FixedBytes { len } => decode_fixed_bytes(name, payload, *len),
        TypeArtifact::FixedArray { item, len } => decode_array_payload(name, item, Some(*len), payload),
        TypeArtifact::DynamicArray { item } => decode_array_payload(name, item, None, payload),
        TypeArtifact::Struct { name } => Err(CodecError::UnsupportedType(format!("state struct {name}"))),
    }
}

fn decode_fixed_bytes(name: &str, payload: &[u8], expected: usize) -> CodecResult<ArtifactValue> {
    require_len(name, expected, payload.len())?;
    Ok(ArtifactValue::Bytes(payload.to_vec()))
}

fn decode_array_payload(name: &str, item: &TypeArtifact, expected_len: Option<usize>, payload: &[u8]) -> CodecResult<ArtifactValue> {
    let item_len = fixed_payload_len(item).ok_or_else(|| CodecError::UnsupportedType(type_name(item)))?;
    if item_len == 0 || !payload.len().is_multiple_of(item_len) {
        return Err(CodecError::InvalidLength { name: name.to_string(), expected: item_len, actual: payload.len() });
    }
    let actual_len = payload.len() / item_len;
    if let Some(expected) = expected_len {
        require_len(name, expected, actual_len)?;
    }
    payload
        .chunks_exact(item_len)
        .map(|chunk| decode_state_payload(name, item, chunk))
        .collect::<CodecResult<Vec<_>>>()
        .map(ArtifactValue::Array)
}

fn encode_array_payload(name: &str, item: &TypeArtifact, expected_len: Option<usize>, value: &ArtifactValue) -> CodecResult<Vec<u8>> {
    if matches!(item, TypeArtifact::Struct { .. }) {
        return Err(CodecError::UnsupportedType(type_name(item)));
    }
    let values = expect_array(value)?;
    if let Some(expected) = expected_len {
        require_len(name, expected, values.len())?;
    }
    let mut out = Vec::new();
    for value in values {
        out.extend(encode_fixed_payload(name, item, value)?);
    }
    Ok(out)
}

fn encode_fixed_payload(name: &str, ty: &TypeArtifact, value: &ArtifactValue) -> CodecResult<Vec<u8>> {
    match ty {
        TypeArtifact::Int => serialize_i64(expect_int(value)?, Some(8)),
        TypeArtifact::Bool => Ok(vec![u8::from(expect_bool(value)?)]),
        TypeArtifact::Byte => Ok(vec![expect_byte(value)?]),
        TypeArtifact::Pubkey => fixed_bytes(name, value, 32),
        TypeArtifact::Sig => fixed_bytes(name, value, 65),
        TypeArtifact::Datasig => fixed_bytes(name, value, 64),
        TypeArtifact::FixedBytes { len } => fixed_bytes(name, value, *len),
        TypeArtifact::FixedArray { item, len } => encode_array_payload(name, item, Some(*len), value),
        TypeArtifact::Bytes | TypeArtifact::Text | TypeArtifact::DynamicArray { .. } | TypeArtifact::Struct { .. } => {
            Err(CodecError::UnsupportedType(type_name(ty)))
        }
    }
}

fn fixed_payload_len(ty: &TypeArtifact) -> Option<usize> {
    match ty {
        TypeArtifact::Int => Some(8),
        TypeArtifact::Bool => Some(1),
        TypeArtifact::Byte => Some(1),
        TypeArtifact::Pubkey => Some(32),
        TypeArtifact::Sig => Some(65),
        TypeArtifact::Datasig => Some(64),
        TypeArtifact::FixedBytes { len } => Some(*len),
        TypeArtifact::FixedArray { item, len } => fixed_payload_len(item).map(|item_len| item_len * len),
        TypeArtifact::Bytes | TypeArtifact::Text | TypeArtifact::DynamicArray { .. } | TypeArtifact::Struct { .. } => None,
    }
}

fn push_fixed_bytes(out: &mut Vec<u8>, name: &str, value: &ArtifactValue, expected: usize) -> CodecResult<()> {
    let bytes = fixed_bytes(name, value, expected)?;
    push_data_canonical(out, &bytes);
    Ok(())
}

fn fixed_bytes(name: &str, value: &ArtifactValue, expected: usize) -> CodecResult<Vec<u8>> {
    let bytes = expect_bytes(value)?;
    require_len(name, expected, bytes.len())?;
    Ok(bytes.to_vec())
}

fn push_i64(out: &mut Vec<u8>, value: i64) -> CodecResult<()> {
    if value == 0 {
        out.push(OP_0);
        return Ok(());
    }
    if value == -1 {
        out.push(OP_1_NEGATE);
        return Ok(());
    }
    if (1..=16).contains(&value) {
        out.push((OP_1 as i64 - 1 + value) as u8);
        return Ok(());
    }
    let bytes = serialize_i64(value, None)?;
    if bytes.len() > 8 {
        return Err(CodecError::InvalidNumber { value, size: 8 });
    }
    push_data_canonical(out, &bytes);
    Ok(())
}

fn push_data_canonical(out: &mut Vec<u8>, data: &[u8]) {
    match data {
        [] => out.push(OP_0),
        [OP_1_NEGATE_VALUE] => out.push(OP_1_NEGATE),
        [1..=16] => out.push((OP_1 - 1) + data[0]),
        _ => push_data_explicit(out, data),
    }
}

fn push_data_explicit(out: &mut Vec<u8>, data: &[u8]) {
    let len = data.len();
    if len == 0 {
        out.push(OP_0);
    } else if len <= OP_DATA_75 as usize {
        out.push((OP_DATA_1 - 1) + len as u8);
    } else if len <= u8::MAX as usize {
        out.push(OP_PUSH_DATA_1);
        out.push(len as u8);
    } else if len <= u16::MAX as usize {
        out.push(OP_PUSH_DATA_2);
        out.extend_from_slice(&(len as u16).to_le_bytes());
    } else {
        out.push(OP_PUSH_DATA_4);
        out.extend_from_slice(&(len as u32).to_le_bytes());
    }
    out.extend_from_slice(data);
}

fn parse_pushes(script: &[u8]) -> CodecResult<Vec<(usize, Vec<u8>)>> {
    let mut pushes = Vec::new();
    let mut offset = 0;
    while offset < script.len() {
        let start = offset;
        let opcode = script[offset];
        offset += 1;
        let len = match opcode {
            OP_0 => {
                pushes.push((start, Vec::new()));
                continue;
            }
            OP_DATA_1..=OP_DATA_75 => opcode as usize,
            OP_PUSH_DATA_1 => {
                let bytes = read_len(script, &mut offset, 1)?;
                bytes[0] as usize
            }
            OP_PUSH_DATA_2 => {
                let bytes = read_len(script, &mut offset, 2)?;
                u16::from_le_bytes([bytes[0], bytes[1]]) as usize
            }
            OP_PUSH_DATA_4 => {
                let bytes = read_len(script, &mut offset, 4)?;
                u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize
            }
            OP_1_NEGATE | OP_1..=OP_16 => {
                return Err(CodecError::InvalidPush(format!("small-int opcode {opcode:#x} is not valid in state span")));
            }
            _ => return Err(CodecError::InvalidPush(format!("opcode {opcode:#x} is not a push-data opcode"))),
        };
        let data = read_len(script, &mut offset, len)?.to_vec();
        pushes.push((start, data));
    }
    Ok(pushes)
}

fn read_len<'a>(script: &'a [u8], offset: &mut usize, len: usize) -> CodecResult<&'a [u8]> {
    let end = offset.checked_add(len).ok_or_else(|| CodecError::InvalidPush("push length overflow".to_string()))?;
    if end > script.len() {
        return Err(CodecError::InvalidPush(format!(
            "push at offset {} needs {} bytes, only {} remain",
            *offset,
            len,
            script.len().saturating_sub(*offset)
        )));
    }
    let bytes = &script[*offset..end];
    *offset = end;
    Ok(bytes)
}

fn serialize_i64(value: i64, size: Option<usize>) -> CodecResult<Vec<u8>> {
    let sign = value.signum();
    let mut positive = value.unsigned_abs();
    let mut last_saturated = false;
    let mut bytes = Vec::with_capacity(size.unwrap_or(8));
    while positive != 0 || last_saturated {
        if positive == 0 {
            bytes.push(0);
            last_saturated = false;
        } else {
            let byte = (positive & 0xff) as u8;
            last_saturated = (byte & 0x80) != 0;
            positive >>= 8;
            bytes.push(byte);
        }
    }

    if let Some(size) = size {
        if bytes.len() > size {
            return Err(CodecError::InvalidNumber { value, size });
        }
        bytes.resize(size, 0);
    }

    if sign == -1 {
        match bytes.last_mut() {
            Some(byte) => *byte |= 0x80,
            None => return Err(CodecError::InvalidNumber { value, size: size.unwrap_or(0) }),
        }
    }
    Ok(bytes)
}

fn deserialize_i64(bytes: &[u8]) -> CodecResult<i64> {
    if bytes.len() > 8 {
        return Err(CodecError::InvalidLength { name: "int".to_string(), expected: 8, actual: bytes.len() });
    }
    if bytes.is_empty() {
        return Ok(0);
    }
    let msb = bytes[bytes.len() - 1];
    let sign = 1 - 2 * ((msb >> 7) as i64);
    let first_byte = (msb & 0x7f) as i64;
    Ok(bytes[..bytes.len() - 1].iter().rev().map(|byte| *byte as i64).fold(first_byte, |accum, byte| (accum << 8) + byte) * sign)
}

fn expect_int(value: &ArtifactValue) -> CodecResult<i64> {
    match value {
        ArtifactValue::Int(value) => Ok(*value),
        other => type_mismatch("int", other),
    }
}

fn expect_bool(value: &ArtifactValue) -> CodecResult<bool> {
    match value {
        ArtifactValue::Bool(value) => Ok(*value),
        other => type_mismatch("bool", other),
    }
}

fn expect_byte(value: &ArtifactValue) -> CodecResult<u8> {
    match value {
        ArtifactValue::Byte(value) => Ok(*value),
        other => type_mismatch("byte", other),
    }
}

fn expect_bytes(value: &ArtifactValue) -> CodecResult<&[u8]> {
    match value {
        ArtifactValue::Bytes(value) => Ok(value),
        other => type_mismatch("bytes", other),
    }
}

fn expect_text(value: &ArtifactValue) -> CodecResult<&str> {
    match value {
        ArtifactValue::Text(value) => Ok(value),
        other => type_mismatch("string", other),
    }
}

fn expect_array(value: &ArtifactValue) -> CodecResult<&[ArtifactValue]> {
    match value {
        ArtifactValue::Array(value) => Ok(value),
        other => type_mismatch("array", other),
    }
}

fn object_fields(value: &ArtifactValue) -> CodecResult<&BTreeMap<String, ArtifactValue>> {
    match value {
        ArtifactValue::Object(fields) => Ok(fields),
        other => type_mismatch("object", other),
    }
}

fn type_mismatch<T>(expected: &str, actual: &ArtifactValue) -> CodecResult<T> {
    Err(CodecError::TypeMismatch { expected: expected.to_string(), actual: value_name(actual).to_string() })
}

fn value_name(value: &ArtifactValue) -> &'static str {
    match value {
        ArtifactValue::Int(_) => "int",
        ArtifactValue::Bool(_) => "bool",
        ArtifactValue::Byte(_) => "byte",
        ArtifactValue::Bytes(_) => "bytes",
        ArtifactValue::Text(_) => "string",
        ArtifactValue::Array(_) => "array",
        ArtifactValue::Object(_) => "object",
    }
}

fn assert_no_extra_fields(fields: &BTreeMap<String, ArtifactValue>, expected: &[FieldArtifact]) -> CodecResult<()> {
    for name in fields.keys() {
        if expected.iter().all(|field| &field.name != name) {
            return Err(CodecError::UnknownField(name.clone()));
        }
    }
    Ok(())
}

fn require_len(name: &str, expected: usize, actual: usize) -> CodecResult<()> {
    if expected == actual { Ok(()) } else { Err(CodecError::InvalidLength { name: name.to_string(), expected, actual }) }
}

fn type_name(ty: &TypeArtifact) -> String {
    match ty {
        TypeArtifact::Int => "int".to_string(),
        TypeArtifact::Bool => "bool".to_string(),
        TypeArtifact::Byte => "byte".to_string(),
        TypeArtifact::Bytes => "bytes".to_string(),
        TypeArtifact::Text => "string".to_string(),
        TypeArtifact::Pubkey => "pubkey".to_string(),
        TypeArtifact::Sig => "sig".to_string(),
        TypeArtifact::Datasig => "datasig".to_string(),
        TypeArtifact::FixedBytes { len } => format!("byte[{len}]"),
        TypeArtifact::FixedArray { item, len } => format!("{}[{len}]", type_name(item)),
        TypeArtifact::DynamicArray { item } => format!("{}[]", type_name(item)),
        TypeArtifact::Struct { name } => name.clone(),
    }
}

fn hex_nibble(byte: u8) -> CodecResult<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(CodecError::InvalidHex(format!("invalid digit `{}`", byte as char))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact::{
        CompiledActorArtifact, CompiledTemplateArtifact, RuntimeFieldArtifact, RuntimeFieldRoleArtifact, SilActorArtifact,
        SilEntryArtifact, StateSpanArtifact,
    };

    #[test]
    fn encodes_pushes_like_silverscript_builder() {
        let artifact = tiny_sil_abi();
        let sigscript = encode_actor_entry_sig_script(
            &artifact,
            "Foo",
            "main",
            &[ArtifactValue::Int(17), ArtifactValue::Bytes(vec![1, 2, 3, 4]), ArtifactValue::Bool(true), ArtifactValue::Byte(1)],
        )
        .expect("sigscript encodes");

        assert_eq!(encode_hex(&sigscript), "01110401020304515100");
    }

    #[test]
    fn rejects_sigscript_ints_that_do_not_fit_silverscript_script_number() {
        let artifact = tiny_sil_abi();
        let err = encode_actor_entry_sig_script(
            &artifact,
            "Foo",
            "main",
            &[ArtifactValue::Int(i64::MIN), ArtifactValue::Bytes(vec![1, 2, 3, 4]), ArtifactValue::Bool(true), ArtifactValue::Byte(1)],
        )
        .expect_err("i64::MIN needs 9 bytes and should match txscript rejection");

        assert_eq!(err, CodecError::InvalidNumber { value: i64::MIN, size: 8 });
    }

    #[test]
    fn round_trips_runtime_state_script() {
        let runtime_state = RuntimeStateArtifact {
            source: "FooState".to_string(),
            fields: vec![
                RuntimeFieldArtifact {
                    name: "gen__template_foo".to_string(),
                    ty: TypeArtifact::FixedBytes { len: 32 },
                    role: RuntimeFieldRoleArtifact::Template { actor: "Foo".to_string() },
                },
                RuntimeFieldArtifact { name: "count".to_string(), ty: TypeArtifact::Int, role: RuntimeFieldRoleArtifact::Source },
                RuntimeFieldArtifact { name: "flag".to_string(), ty: TypeArtifact::Bool, role: RuntimeFieldRoleArtifact::Source },
            ],
        };
        let values = BTreeMap::from([
            ("gen__template_foo".to_string(), ArtifactValue::Bytes(vec![7; 32])),
            ("count".to_string(), ArtifactValue::Int(-5)),
            ("flag".to_string(), ArtifactValue::Bool(true)),
        ]);

        let encoded = encode_runtime_state_script(&runtime_state, &values).expect("state encodes");
        let decoded = decode_runtime_state_script(&runtime_state, &encoded).expect("state decodes");

        assert_eq!(decoded, values);
        assert_eq!(encode_runtime_state_script(&runtime_state, &decoded).expect("state re-encodes"), encoded);

        let mut extra = values;
        extra.insert("extra".to_string(), ArtifactValue::Int(1));
        assert_eq!(
            encode_runtime_state_script(&runtime_state, &extra).expect_err("extra fields should be rejected"),
            CodecError::UnknownField("extra".to_string())
        );
    }

    fn tiny_sil_abi() -> SilAbiArtifact {
        SilAbiArtifact {
            schema_version: 1,
            states: Vec::new(),
            actors: vec![SilActorArtifact {
                name: "Foo".to_string(),
                source_path: "sil/Foo.sil".to_string(),
                runtime_state: RuntimeStateArtifact { source: "FooState".to_string(), fields: Vec::new() },
                entries: vec![
                    SilEntryArtifact {
                        name: "main".to_string(),
                        selector: Some(0),
                        user_params: vec![
                            param("n", TypeArtifact::Int),
                            param("hash", TypeArtifact::FixedBytes { len: 4 }),
                            param("flag", TypeArtifact::Bool),
                            param("b", TypeArtifact::Byte),
                        ],
                        hidden_params: Vec::new(),
                    },
                    SilEntryArtifact {
                        name: "other".to_string(),
                        selector: Some(1),
                        user_params: Vec::new(),
                        hidden_params: Vec::new(),
                    },
                ],
                compiled: CompiledActorArtifact {
                    script_hex: String::new(),
                    template: CompiledTemplateArtifact {
                        prefix_hex: String::new(),
                        suffix_hex: String::new(),
                        hash_hex: String::new(),
                    },
                    state_span: StateSpanArtifact { offset: 0, len: 0 },
                },
            }],
        }
    }

    fn param(name: &str, ty: TypeArtifact) -> crate::artifact::ParamArtifact {
        crate::artifact::ParamArtifact { name: name.to_string(), ty }
    }
}
