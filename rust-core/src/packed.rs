const FORMAT_VERSION: u8 = 0x01;
const RING_COMMITMENT_LEN: usize = 144;
const RING_KEY_COMMITMENT_LEN: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodecError {
    Malformed(String),
}

impl CodecError {
    fn malformed(reason: impl Into<String>) -> Self {
        Self::Malformed(reason.into())
    }
}

impl std::fmt::Display for CodecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(message) => write!(f, "{message}"),
        }
    }
}

impl std::error::Error for CodecError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BvrfRingPrepareOutput {
    pub handle: u32,
    pub commitment: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BvrfBatchVerifyItem {
    pub proof: Vec<u8>,
    pub key_commitment: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BvrfIetfVerifyRequest {
    pub public_key: Vec<u8>,
    pub input: Vec<u8>,
    pub proof: Vec<u8>,
    pub aux: Vec<u8>,
}

struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    fn new() -> Self {
        Self {
            buf: vec![FORMAT_VERSION],
        }
    }

    fn u8(&mut self, value: u8) {
        self.buf.push(value);
    }

    fn u32(&mut self, value: u32) {
        self.buf.extend_from_slice(&value.to_le_bytes());
    }

    fn blob(&mut self, bytes: &[u8]) {
        let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
        self.u32(len);
        let written = (len as usize).min(bytes.len());
        self.buf.extend_from_slice(&bytes[..written]);
    }

    fn raw(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    fn finish(self) -> Vec<u8> {
        self.buf
    }
}

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Result<Self, CodecError> {
        let mut reader = Self { data, pos: 0 };
        let version = reader.u8()?;
        if version != FORMAT_VERSION {
            return Err(CodecError::malformed(format!(
                "unsupported packed format version {version}"
            )));
        }
        Ok(reader)
    }

    fn read_exact(&mut self, n: usize) -> Result<&'a [u8], CodecError> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or_else(|| CodecError::malformed("malformed packed payload: length overflow"))?;
        if end > self.data.len() {
            return Err(CodecError::malformed("malformed packed payload: truncated"));
        }
        let slice = &self.data[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8, CodecError> {
        let bytes = self.read_exact(1)?;
        Ok(bytes[0])
    }

    fn u32(&mut self) -> Result<u32, CodecError> {
        let bytes = self.read_exact(4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn blob(&mut self) -> Result<Vec<u8>, CodecError> {
        let len = self.u32()? as usize;
        Ok(self.read_exact(len)?.to_vec())
    }

    fn utf8_blob(&mut self) -> Result<String, CodecError> {
        let bytes = self.blob()?;
        String::from_utf8(bytes)
            .map_err(|_| CodecError::malformed("malformed packed payload: invalid utf-8"))
    }

    fn raw(&mut self, n: usize) -> Result<Vec<u8>, CodecError> {
        Ok(self.read_exact(n)?.to_vec())
    }

    fn finish(self) -> Result<(), CodecError> {
        if self.pos != self.data.len() {
            return Err(CodecError::malformed(
                "malformed packed payload: trailing bytes",
            ));
        }
        Ok(())
    }
}

pub fn encode_bvrf_srs_open_request(path: &str) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.blob(path.as_bytes());
    writer.finish()
}

pub fn decode_bvrf_srs_open_request(bytes: &[u8]) -> Result<String, CodecError> {
    let mut reader = Reader::new(bytes)?;
    let path = reader.utf8_blob()?;
    reader.finish()?;
    Ok(path)
}

pub fn encode_bvrf_srs_open_output(handle: u32) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.u32(handle);
    writer.finish()
}

pub fn decode_bvrf_srs_open_output(bytes: &[u8]) -> Result<u32, CodecError> {
    let mut reader = Reader::new(bytes)?;
    let handle = reader.u32()?;
    reader.finish()?;
    Ok(handle)
}

pub fn encode_bvrf_ring_prepare_request(ring_keys: &[u8]) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.blob(ring_keys);
    writer.finish()
}

pub fn decode_bvrf_ring_prepare_request(bytes: &[u8]) -> Result<Vec<u8>, CodecError> {
    let mut reader = Reader::new(bytes)?;
    let ring_keys = reader.blob()?;
    reader.finish()?;
    Ok(ring_keys)
}

pub fn encode_bvrf_ring_prepare_output(
    handle: u32,
    commitment: &[u8],
) -> Result<Vec<u8>, CodecError> {
    if commitment.len() != RING_COMMITMENT_LEN {
        return Err(CodecError::malformed(format!(
            "malformed packed payload: ring commitment must be {RING_COMMITMENT_LEN} bytes, got {}",
            commitment.len()
        )));
    }
    let mut writer = Writer::new();
    writer.u32(handle);
    writer.raw(commitment);
    Ok(writer.finish())
}

pub fn decode_bvrf_ring_prepare_output(bytes: &[u8]) -> Result<BvrfRingPrepareOutput, CodecError> {
    let mut reader = Reader::new(bytes)?;
    let handle = reader.u32()?;
    let commitment = reader.raw(RING_COMMITMENT_LEN)?;
    reader.finish()?;
    Ok(BvrfRingPrepareOutput { handle, commitment })
}

pub fn encode_bvrf_batch_verify_items(
    items: &[BvrfBatchVerifyItem],
) -> Result<Vec<u8>, CodecError> {
    let mut writer = Writer::new();
    let count = u32::try_from(items.len()).unwrap_or(u32::MAX);
    writer.u32(count);
    let written = (count as usize).min(items.len());
    for item in items.iter().take(written) {
        if item.key_commitment.len() != RING_KEY_COMMITMENT_LEN {
            return Err(CodecError::malformed(format!(
                "malformed packed payload: key commitment must be {RING_KEY_COMMITMENT_LEN} bytes, got {}",
                item.key_commitment.len()
            )));
        }
        writer.blob(&item.proof);
        writer.raw(&item.key_commitment);
    }
    Ok(writer.finish())
}

pub fn decode_bvrf_batch_verify_items(
    bytes: &[u8],
) -> Result<Vec<BvrfBatchVerifyItem>, CodecError> {
    let mut reader = Reader::new(bytes)?;
    let count = reader.u32()? as usize;
    let mut items = Vec::with_capacity(count.min(1024));
    for _ in 0..count {
        items.push(BvrfBatchVerifyItem {
            proof: reader.blob()?,
            key_commitment: reader.raw(RING_KEY_COMMITMENT_LEN)?,
        });
    }
    reader.finish()?;
    Ok(items)
}

pub fn encode_bvrf_ietf_verify_request(request: &BvrfIetfVerifyRequest) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.blob(&request.public_key);
    writer.blob(&request.input);
    writer.blob(&request.proof);
    writer.blob(&request.aux);
    writer.finish()
}

pub fn decode_bvrf_ietf_verify_request(bytes: &[u8]) -> Result<BvrfIetfVerifyRequest, CodecError> {
    let mut reader = Reader::new(bytes)?;
    let request = BvrfIetfVerifyRequest {
        public_key: reader.blob()?,
        input: reader.blob()?,
        proof: reader.blob()?,
        aux: reader.blob()?,
    };
    reader.finish()?;
    Ok(request)
}

pub fn encode_bvrf_validity(valid: bool) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.u8(u8::from(valid));
    writer.finish()
}

pub fn decode_bvrf_validity(bytes: &[u8]) -> Result<bool, CodecError> {
    let mut reader = Reader::new(bytes)?;
    let flag = reader.u8()?;
    reader.finish()?;
    match flag {
        0 => Ok(false),
        1 => Ok(true),
        other => Err(CodecError::malformed(format!(
            "malformed packed payload: invalid validity byte {other}"
        ))),
    }
}

pub fn encode_bvrf_last_error(message: &str) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.blob(message.as_bytes());
    writer.finish()
}

pub fn decode_bvrf_last_error(bytes: &[u8]) -> Result<String, CodecError> {
    let mut reader = Reader::new(bytes)?;
    let message = reader.utf8_blob()?;
    reader.finish()?;
    Ok(message)
}
