pub struct UnicodeString {
    data_length: u16,
    reserved: u32,
    string: Vec<u16>
}