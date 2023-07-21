
pub fn bytes_to_u8(data: &[u8]) -> u8 {
    assert_eq!(data.len(), 1);
    let mut buffer = [0u8; 1];
    buffer.copy_from_slice(data[..].as_ref());
    u8::from_be_bytes(buffer)
}

pub fn bytes_to_u32(data: &[u8]) -> u32 {
    assert_eq!(data.len(), 4);
    let mut buffer = [0u8; 4];
    buffer.copy_from_slice(data[..].as_ref());
    u32::from_be_bytes(buffer)
}
