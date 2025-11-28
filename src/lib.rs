//! # can_decode
//!
//! Decode and encode CAN frames into messages/signals in a fast and easy way.
//!
//! ## Features
//!
//! - Parse DBC (CAN Database) files
//! - Decode CAN messages into signals with physical values
//! - Encode signal values back into raw CAN messages
//! - Support for both standard and extended CAN IDs
//! - Handle big-endian and little-endian byte ordering
//! - Support for signed and unsigned signal values
//! - Apply scaling factors and offsets (and inverse for encoding)
//!
//! ## Decoding Example
//!
//! ```no_run
//! use can_decode::Parser;
//! use std::path::Path;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Load a DBC file
//! let parser = Parser::from_dbc_file(Path::new("my_can_database.dbc"))?;
//!
//! // Decode a CAN message
//! let msg_id = 0x123;
//! let data = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];
//!
//! if let Some(decoded) = parser.decode_msg(msg_id, &data) {
//!     println!("Message: {}", decoded.name);
//!     for (signal_name, signal) in &decoded.signals {
//!         println!("  {}: {} {}", signal_name, signal.value, signal.unit);
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Encoding Example
//!
//! ```no_run
//! use can_decode::Parser;
//! use std::path::Path;
//! use std::collections::HashMap;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let parser = Parser::from_dbc_file(Path::new("my_can_database.dbc"))?;
//!
//! // Encode a CAN message from signal values
//! let mut signal_values = HashMap::from([
//!     ("EngineSpeed".to_string(), 2500.0),
//!     ("ThrottlePosition".to_string(), 45.5),
//! ]);
//!
//! if let Some(data) = parser.encode_msg(0x123, &signal_values) {
//!     println!("Encoded CAN data: {:02X?}", data);
//! }
//!
//! // Or encode by message name
//! if let Some((msg_id, data)) = parser.encode_msg_by_name("EngineData", &signal_values) {
//!     println!("Message ID: {:#X}, Data: {:02X?}", msg_id, data);
//! }
//! # Ok(())
//! # }
//! ```

/// A decoded CAN message containing signal values.
///
/// This structure represents a fully decoded CAN message with all its signals
/// extracted and converted to physical values.
#[derive(Debug, Clone)]
pub struct DecodedMessage {
    /// The name of the message as defined in the DBC file
    pub name: String,
    /// The CAN message ID
    pub msg_id: u32,
    /// Whether this is an extended (29-bit) CAN ID
    pub is_extended: bool,
    /// Transmitting node of the message ("Unknown" if not specified)
    pub tx_node: String,
    /// Map of signal names to their decoded values
    pub signals: std::collections::HashMap<String, DecodedSignal>,
}

/// A decoded signal with its physical value.
///
/// Represents a single signal from a CAN message after decoding and applying
/// scaling/offset transformations.
#[derive(Debug, Clone)]
pub struct DecodedSignal {
    /// The name of the signal as defined in the DBC file
    pub name: String,
    /// The physical value after applying factor and offset
    pub value: f64,
    /// The unit of measurement (e.g., "km/h", "°C", "RPM")
    pub unit: String,
}

#[derive(thiserror::Error, Debug)]
pub enum ParseError {
    /// Failed to read a file
    #[error("Failed to read file: {0}")]
    Io(#[from] std::io::Error),

    /// Failed to parse file as UTF-8
    #[error("Invalid UTF-8 in file: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),

    /// Failed to parse DBC content
    #[error("Failed to parse DBC: {0}")]
    DbcParse(#[from] can_dbc::DbcError),
}

/// A CAN message parser that uses DBC file definitions.
///
/// The parser loads message and signal definitions from DBC files and uses them
/// to decode raw CAN frame data into structured messages with physical signal values.
///
/// # Example
///
/// ```no_run
/// use can_decode::Parser;
/// use std::path::Path;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let mut parser = Parser::new();
/// parser.add_from_dbc_file(Path::new("engine.dbc"))?;
/// parser.add_from_dbc_file(Path::new("transmission.dbc"))?;
///
/// let data = [0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70];
/// if let Some(decoded) = parser.decode_msg(0x100, &data) {
///     println!("Decoded message: {}", decoded.name);
/// }
/// # Ok(())
/// # }
/// ```
pub struct Parser {
    /// Map of message ID to message definitions
    msg_defs: std::collections::HashMap<u32, can_dbc::Message>,
}

impl Parser {
    /// Creates a new empty parser.
    ///
    /// Use [`add_from_dbc_file`](Parser::add_from_dbc_file) or
    /// [`add_from_str`](Parser::add_from_str) to add message definitions.
    ///
    /// # Example
    ///
    /// ```
    /// use can_decode::Parser;
    ///
    /// let parser = Parser::new();
    /// ```
    pub fn new() -> Self {
        Self {
            msg_defs: std::collections::HashMap::new(),
        }
    }

    /// Creates a parser and loads definitions from a DBC file.
    ///
    /// This is a convenience method that combines [`new`](Parser::new) and
    /// [`add_from_str`](Parser::add_from_str).
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the DBC file
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or parsed.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use can_decode::Parser;
    /// use std::path::Path;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let parser = Parser::from_dbc_file(Path::new("my_database.dbc"))?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn from_dbc_file(path: &std::path::Path) -> Result<Self, ParseError> {
        let mut parser = Self::new();
        parser.add_from_dbc_file(path)?;
        Ok(parser)
    }

    /// Adds message definitions from a DBC file string.
    ///
    /// This method parses DBC content from a string slice and adds all message
    /// definitions to the parser. If a message ID already exists, it will be
    /// overwritten and a warning will be logged.
    ///
    /// # Arguments
    ///
    /// * `buffer` - String slice containing the full DBC file contents
    ///
    /// # Errors
    ///
    /// Returns an error if the DBC content cannot be parsed.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use can_decode::Parser;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let dbc_content = "VERSION \"\"..."; // DBC file content as &str
    /// let mut parser = Parser::new();
    /// parser.add_from_str(dbc_content)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn add_from_str(&mut self, buffer: &str) -> Result<(), can_dbc::DbcError> {
        let dbc = can_dbc::Dbc::try_from(buffer)?;
        for msg_def in dbc.messages {
            let msg_id = match msg_def.id {
                can_dbc::MessageId::Standard(id) => id as u32,
                can_dbc::MessageId::Extended(id) => id,
            };
            if self.msg_defs.contains_key(&msg_id) {
                log::warn!(
                    "Duplicate message ID {msg_id:#X} ({}). Overwriting existing definition.",
                    msg_def.name
                );
            }
            self.msg_defs.insert(msg_id, msg_def.clone());
        }
        Ok(())
    }

    /// Adds message definitions from a DBC file.
    ///
    /// Reads and parses a DBC file from disk, adding all message definitions
    /// to the parser. Multiple DBC files can be loaded to combine definitions
    /// from different sources.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the DBC file
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or parsed.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use can_decode::Parser;
    /// use std::path::Path;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut parser = Parser::new();
    /// parser.add_from_dbc_file(Path::new("vehicle.dbc"))?;
    /// parser.add_from_dbc_file(Path::new("diagnostics.dbc"))?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn add_from_dbc_file(&mut self, path: &std::path::Path) -> Result<(), ParseError> {
        let s = std::fs::read_to_string(path)?;
        self.add_from_str(&s)?;
        Ok(())
    }

    /// Decodes a raw CAN message into structured data.
    ///
    /// Takes a CAN message ID and raw data bytes, then decodes all signals
    /// according to the DBC definitions. Each signal is extracted, scaled,
    /// and converted to its physical value.
    ///
    /// # Arguments
    ///
    /// * `msg_id` - The CAN message identifier
    /// * `data` - The raw message data bytes (typically 0-8 bytes for standard CAN)
    ///
    /// # Returns
    ///
    /// Returns `Some(DecodedMessage)` if the message ID is known, or `None` if
    /// the message ID is not found in the loaded DBC definitions.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use can_decode::Parser;
    /// use std::path::Path;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let parser = Parser::from_dbc_file(Path::new("my_database.dbc"))?;
    ///
    /// let msg_id = 0x123;
    /// let data = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];
    ///
    /// if let Some(decoded) = parser.decode_msg(msg_id, &data) {
    ///     println!("Message: {} (ID: {:#X})", decoded.name, decoded.msg_id);
    ///     for (name, signal) in &decoded.signals {
    ///         println!("  {}: {} {}", name, signal.value, signal.unit);
    ///     }
    /// } else {
    ///     println!("Unknown message ID: {:#X}", msg_id);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn decode_msg(&self, msg_id: u32, data: &[u8]) -> Option<DecodedMessage> {
        // Grab msg metadata and then for every signal in the message, decode it and add
        // to the decoded message
        let msg_def = self.msg_defs.get(&msg_id)?;
        let is_extended = matches!(msg_def.id, can_dbc::MessageId::Extended(_));
        let tx_node = match &msg_def.transmitter {
            can_dbc::Transmitter::NodeName(name) => name.clone(),
            can_dbc::Transmitter::VectorXXX => "Unknown".to_string(),
        };
        let mut decoded_signals = std::collections::HashMap::new();

        for signal_def in &msg_def.signals {
            match self.decode_signal(signal_def, data) {
                Some(decoded_signal) => {
                    decoded_signals.insert(decoded_signal.name.to_string(), decoded_signal);
                }
                None => {
                    log::error!(
                        "Failed to decode signal {} from message {}",
                        signal_def.name,
                        msg_def.name
                    );
                    return None;
                }
            }
        }

        Some(DecodedMessage {
            name: msg_def.name.clone(),
            msg_id,
            is_extended,
            tx_node,
            signals: decoded_signals,
        })
    }

    /// Decodes a single signal from raw CAN data.
    ///
    /// Extracts the raw bits for a signal, converts to signed/unsigned as needed,
    /// and applies the scaling factor and offset to produce the physical value.
    fn decode_signal(&self, signal_def: &can_dbc::Signal, data: &[u8]) -> Option<DecodedSignal> {
        // Extract raw value based on byte order and signal properties
        let raw_value = self.extract_signal_value(
            data,
            signal_def.start_bit as usize,
            signal_def.size as usize,
            signal_def.byte_order,
        )?;

        // Convert to signed if needed
        let raw_value = if signal_def.value_type == can_dbc::ValueType::Signed {
            // Convert to signed based on signal size
            let max_unsigned = (1u64 << signal_def.size) - 1;
            let sign_bit = 1u64 << (signal_def.size - 1);

            if raw_value & sign_bit != 0 {
                // Negative number - extend sign
                (raw_value | (!max_unsigned)) as i64 as f64
            } else {
                raw_value as f64
            }
        } else {
            raw_value as f64
        };

        // Apply scaling
        let scaled_value = raw_value * signal_def.factor + signal_def.offset;

        Some(DecodedSignal {
            name: signal_def.name.clone(),
            value: scaled_value,
            unit: signal_def.unit.clone(),
        })
    }

    /// Extracts raw signal bits from CAN data.
    ///
    /// Handles both little-endian and big-endian byte ordering according to
    /// the signal definition.
    fn extract_signal_value(
        &self,
        data: &[u8],
        start_bit: usize,
        size: usize,
        byte_order: can_dbc::ByteOrder,
    ) -> Option<u64> {
        if data.is_empty() || size == 0 {
            return None;
        }

        let total_bits = data.len() * 8;
        if start_bit + size > total_bits {
            return None;
        }

        let mut result = 0u64;

        match byte_order {
            can_dbc::ByteOrder::LittleEndian => {
                let start_byte = start_bit / 8;
                let start_bit_in_byte = start_bit % 8;

                let mut remaining_bits = size;
                let mut current_byte = start_byte;
                let mut bit_offset = start_bit_in_byte;

                while remaining_bits > 0 && current_byte < data.len() {
                    let bits_in_this_byte = std::cmp::min(remaining_bits, 8 - bit_offset);
                    let mask = ((1u64 << bits_in_this_byte) - 1) << bit_offset;
                    let byte_value = ((data[current_byte] as u64) & mask) >> bit_offset;

                    result |= byte_value << (size - remaining_bits);

                    remaining_bits -= bits_in_this_byte;
                    current_byte += 1;
                    bit_offset = 0;
                }
            }
            can_dbc::ByteOrder::BigEndian => {
                // Big-endian (Motorola) bit extraction: iterate bits from
                // start_bit toward higher bit positions, collecting each bit
                // and appending into the result MSB-first.
                let mut bit_pos = start_bit;

                for _ in 0..size {
                    let byte_idx = bit_pos / 8;
                    let bit_idx = 7 - (bit_pos % 8);

                    if byte_idx >= data.len() {
                        break;
                    }

                    let bit_val = (data[byte_idx] >> bit_idx) & 1;
                    result = (result << 1) | (bit_val as u64);

                    bit_pos += 1;
                }
            }
        }

        Some(result)
    }

    /// Encodes a CAN message from signal values into raw bytes.
    ///
    /// Takes a message ID and a map of signal names to their physical values,
    /// then encodes them according to the DBC definitions into raw CAN data bytes.
    /// Applies inverse scaling (offset and factor) and packs bits according to
    /// the signal's byte order and position. Applies scaling factors.
    ///
    /// # Arguments
    ///
    /// * `msg_id` - The CAN message identifier
    /// * `signal_values` - Map of signal names to their physical values
    ///
    /// # Returns
    ///
    /// Returns `Some(Vec<u8>)` containing the encoded message data, or `None` if
    /// the message ID is not found in the loaded DBC definitions or encoding fails.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use can_decode::Parser;
    /// use std::path::Path;
    /// use std::collections::HashMap;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let parser = Parser::from_dbc_file(Path::new("my_database.dbc"))?;
    ///
    /// let signal_values = HashMap::from([
    ///     ("EngineSpeed".to_string(), 2500.0),
    ///     ("ThrottlePosition".to_string(), 45.5),
    /// ]);
    ///
    /// if let Some(data) = parser.encode_msg(0x123, &signal_values) {
    ///     println!("Encoded data: {:02X?}", data);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn encode_msg(
        &self,
        msg_id: u32,
        signal_values: &std::collections::HashMap<String, f64>,
    ) -> Option<Vec<u8>> {
        let msg_def = self.msg_defs.get(&msg_id)?;

        let msg_size = msg_def.size as usize;
        let mut data = vec![0u8; msg_size];

        for signal_def in &msg_def.signals {
            let physical_value = match signal_values.get(&signal_def.name) {
                Some(&v) => v,
                None => {
                    log::error!(
                        "Signal {} not provided for message {} during encoding",
                        signal_def.name,
                        msg_def.name
                    );
                    return None;
                }
            };

            // encode_signal() modifies the data buffer in place
            if self
                .encode_signal(signal_def, physical_value, &mut data)
                .is_none()
            {
                log::error!(
                    "Failed to encode signal {} for message {}",
                    signal_def.name,
                    msg_def.name
                );
                return None;
            }
        }

        Some(data)
    }

    /// Encodes a CAN message by message name instead of ID.
    ///
    /// Looks up the message by name and then encode it. This is slower as it
    /// requires searching through all loaded messages. Applies scaling factors.
    ///
    /// # Arguments
    ///
    /// * `msg_name` - The name of the message as defined in the DBC file
    /// * `signal_values` - Map of signal names to their physical values
    ///
    /// # Returns
    ///
    /// Returns `Some((msg_id, data))` containing the message ID and encoded data,
    /// or `None` if the message name is not found or encoding fails.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use can_decode::Parser;
    /// use std::path::Path;
    /// use std::collections::HashMap;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let parser = Parser::from_dbc_file(Path::new("my_database.dbc"))?;
    ///
    /// let signal_values = HashMap::from([
    ///     ("EngineSpeed".to_string(), 2500.0),
    ///     ("ThrottlePosition".to_string(), 45.5),
    /// ]);
    ///
    /// if let Some((msg_id, data)) = parser.encode_msg_by_name("EngineData", &signal_values) {
    ///     println!("Message ID: {:#X}, Data: {:02X?}", msg_id, data);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn encode_msg_by_name(
        &self,
        msg_name: &str,
        signal_values: &std::collections::HashMap<String, f64>,
    ) -> Option<(u32, Vec<u8>)> {
        let (msg_id, _msg_def) = self
            .msg_defs
            .iter()
            .find(|(_id, msg)| msg.name == msg_name)?;

        let data = self.encode_msg(*msg_id, signal_values)?;
        Some((*msg_id, data))
    }

    /// Encodes a single signal into raw CAN data.
    ///
    /// Applies inverse scaling (subtracts offset, divides by factor), converts to
    /// the appropriate integer representation, and packs the bits into the data buffer.
    fn encode_signal(
        &self,
        signal_def: &can_dbc::Signal,
        physical_value: f64,
        data: &mut [u8],
    ) -> Option<()> {
        // Apply inverse scaling: raw = (physical - offset) / factor
        let raw_value = (physical_value - signal_def.offset) / signal_def.factor;

        // Convert to integer and handle signed/unsigned
        let raw_int = if signal_def.value_type == can_dbc::ValueType::Signed {
            // Convert signed physical value to the integer representation
            // then to the unsigned bit pattern (two's complement).
            let signed_val = raw_value.round() as i64;
            // For an N-bit signed value the allowed signed range is
            // -(1 << (N-1)) .. (1 << (N-1)) - 1
            let max_value = (1i64 << (signal_def.size - 1)) - 1;
            let min_value = -(1i64 << (signal_def.size - 1));

            // Clamp to valid signed range
            let clamped = signed_val.max(min_value).min(max_value);

            // Convert to unsigned representation (two's complement)
            if clamped < 0 {
                let mask = (1u64 << signal_def.size) - 1;
                (clamped as u64) & mask
            } else {
                clamped as u64
            }
        } else {
            // Unsigned value
            let unsigned_val = raw_value.round() as u64;
            let max_value = (1u64 << signal_def.size) - 1;

            // Clamp to valid range
            unsigned_val.min(max_value)
        };

        // Insert the value into the data buffer
        self.insert_signal_value(
            data,
            signal_def.start_bit as usize,
            signal_def.size as usize,
            signal_def.byte_order,
            raw_int,
        )
    }

    /// Inserts raw signal bits into CAN data.
    ///
    /// Handles both little-endian and big-endian byte ordering according to
    /// the signal definition.
    fn insert_signal_value(
        &self,
        data: &mut [u8],
        start_bit: usize,
        size: usize,
        byte_order: can_dbc::ByteOrder,
        value: u64,
    ) -> Option<()> {
        if data.is_empty() || size == 0 {
            return None;
        }

        let total_bits = data.len() * 8;
        if start_bit + size > total_bits {
            return None;
        }

        match byte_order {
            can_dbc::ByteOrder::LittleEndian => {
                let start_byte = start_bit / 8;
                let start_bit_in_byte = start_bit % 8;

                let mut remaining_bits = size;
                let mut current_byte = start_byte;
                let mut bit_offset = start_bit_in_byte;
                let mut value_offset = 0;

                while remaining_bits > 0 && current_byte < data.len() {
                    let bits_in_this_byte = std::cmp::min(remaining_bits, 8 - bit_offset);
                    let mask = ((1u8 << bits_in_this_byte) - 1) << bit_offset;

                    // Extract bits from value
                    let value_bits =
                        ((value >> value_offset) & ((1u64 << bits_in_this_byte) - 1)) as u8;

                    // Clear the bits in the data byte and set new bits
                    data[current_byte] =
                        (data[current_byte] & !mask) | ((value_bits << bit_offset) & mask);

                    remaining_bits -= bits_in_this_byte;
                    value_offset += bits_in_this_byte;
                    current_byte += 1;
                    bit_offset = 0;
                }
            }
            can_dbc::ByteOrder::BigEndian => {
                // Big-endian (Motorola) bit insertion: iterate bits from
                // start_bit toward higher bit positions, extracting each bit
                // from value MSB-first.
                let mut bit_pos = start_bit;

                for i in 0..size {
                    let byte_idx = bit_pos / 8;
                    let bit_idx = 7 - (bit_pos % 8);

                    if byte_idx >= data.len() {
                        break;
                    }

                    // Extract bit from value (MSB first)
                    let bit_val = ((value >> (size - 1 - i)) & 1) as u8;

                    // Clear the bit and set new value
                    let mask = 1u8 << bit_idx;
                    data[byte_idx] = (data[byte_idx] & !mask) | ((bit_val << bit_idx) & mask);

                    bit_pos += 1;
                }
            }
        }

        Some(())
    }

    /// Returns all signal definitions for a given message ID.
    ///
    /// # Arguments
    ///
    /// * `msg_id` - The CAN message identifier
    ///
    /// # Returns
    ///
    /// Returns `Some(Vec<Signal>)` if the message ID is known, or `None` otherwise.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use can_decode::Parser;
    /// use std::path::Path;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let parser = Parser::from_dbc_file(Path::new("my_database.dbc"))?;
    ///
    /// if let Some(signals) = parser.signal_defs(0x123) {
    ///     for signal in signals {
    ///         println!("Signal: {}", signal.name);
    ///     }
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn signal_defs(&self, msg_id: u32) -> Option<Vec<can_dbc::Signal>> {
        let msg_def = self.msg_defs.get(&msg_id)?;
        Some(msg_def.signals.to_vec())
    }

    /// Returns all loaded message definitions.
    ///
    /// # Returns
    ///
    /// A vector containing all message definitions that have been loaded
    /// from DBC files.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use can_decode::Parser;
    /// use std::path::Path;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let parser = Parser::from_dbc_file(Path::new("my_database.dbc"))?;
    ///
    /// for msg in parser.msg_defs() {
    ///     println!("Message: {} (ID: {:#X})", msg.name,
    ///              match msg.id {
    ///                  can_dbc::MessageId::Standard(id) => id as u32,
    ///                  can_dbc::MessageId::Extended(id) => id,
    ///              });
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn msg_defs(&self) -> Vec<can_dbc::Message> {
        self.msg_defs.values().cloned().collect()
    }

    /// Returns the message definition for a given message ID.
    ///
    /// # Arguments
    ///
    /// * `msg_id` - The CAN message identifier
    ///
    /// # Returns
    ///
    /// Returns a reference to the message definition if found, or `None` if
    /// the message ID is not known.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use can_decode::Parser;
    /// use std::path::Path;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let parser = Parser::from_dbc_file(Path::new("my_database.dbc"))?;
    ///
    /// if let Some(msg_def) = parser.msg_def(0x123) {
    ///     println!("Message: {}", msg_def.name);
    /// }
    /// # Ok(())
    /// # }
    ///
    pub fn msg_def(&self, msg_id: u32) -> Option<&can_dbc::Message> {
        self.msg_defs.get(&msg_id)
    }

    /// Clears all loaded message definitions.
    ///
    /// After calling this method, the parser will have no message definitions
    /// and will need to reload DBC files.
    ///
    /// # Example
    ///
    /// ```
    /// use can_decode::Parser;
    ///
    /// let mut parser = Parser::new();
    /// parser.clear();
    /// ```
    pub fn clear(&mut self) {
        self.msg_defs.clear();
    }
}

impl Default for Parser {
    fn default() -> Self {
        Self::new()
    }
}
