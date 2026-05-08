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
//! - Decode/encode IEEE-754 float signals (`SIG_VALTYPE_`)
//! - Support for DBC enumerations (value descriptions) to map raw values to string labels
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
//!         println!("  {}: {:?} {}", signal_name, signal.value, signal.unit);
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
//! let signal_values = HashMap::from([
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

pub use can_dbc;

/// Creates a bitmask with the lowest N bits set to 1.
///
/// This macro generates a mask value of the specified type with the lower `bits` bits set to 1
/// and all other bits set to 0. It's used internally for extracting or masking the lower portion of
/// integer values.
///
/// # Arguments
///
/// * `$bits` - The number of low bits to set (must be <= the bit width of the type)
/// * `$ty` - The integer type for the mask (e.g., u8, u16, u32, u64)
///
/// # Examples
///
/// ```ignore
/// let mask = low_bits_mask!(4, u8);  // Returns 0b00001111 (15)
/// let mask = low_bits_mask!(8, u8);  // Returns 0b11111111 (255)
/// let mask = low_bits_mask!(0, u16); // Returns 0
/// ```
///
/// # Panics
///
/// Panics in debug builds if `bits` exceeds the bit width of the specified type.
macro_rules! low_bits_mask {
    ($bits:expr, $ty:ty) => {{
        debug_assert!($bits <= <$ty>::BITS as usize);
        match $bits {
            0 => 0 as $ty,
            n if n == <$ty>::BITS as usize => <$ty>::MAX,
            n => <$ty>::MAX >> (<$ty>::BITS as usize - n),
        }
    }};
}

/// Type alias for the ordered map of signals returned by decoding.
///
/// This allows downstream crates to reference the signal map type without
/// needing to add indexmap as a dependency.
pub type SignalMap = indexmap::map::IndexMap<String, DecodedSignal>;
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
    /// Ordered map of signal names to their decoded values (maintains insertion order)
    pub signals: SignalMap,
}

/// Represents the decoded value of a CAN signal.
#[derive(Debug, Clone)]
pub struct DecodedSignalValue {
    /// The physical value of the signal after applying scaling and offset.
    pub physical: f64,
    /// Contains the raw integer value (with sign accounting).
    /// Present unless the signal is an IEEE float/double.
    pub raw: Option<i128>,
    /// If the signal/value has an enum mapping, this contains the corresponding enum label.
    pub enum_label: Option<String>,
}

impl DecodedSignalValue {
    /// Creates a new `DecodedSignalValue` for a numeric signal that is backed by
    /// an integer (signed or unsigned).
    pub fn new_integer_backed_numeric(physical: f64, raw_value: i128) -> Self {
        Self {
            physical,
            raw: Some(raw_value),
            enum_label: None,
        }
    }

    /// Creates a new `DecodedSignalValue` for a numeric signal that is backed
    /// by an IEEE-754 float/double.
    pub fn new_float_backed_numeric(physical: f64) -> Self {
        Self {
            physical,
            raw: None,
            enum_label: None,
        }
    }

    /// Creates a new `DecodedSignalValue` for an enumerated signal.
    pub fn new_enum(physical: f64, raw_value: i128, enum_label: String) -> Self {
        Self {
            physical,
            raw: Some(raw_value),
            enum_label: Some(enum_label),
        }
    }
}

/// A decoded signal with its physical value.
///
/// Represents a single signal from a CAN message after decoding. The value is
/// either a numeric physical value (after scaling/offset) or an enum label from
/// DBC value descriptions.
#[derive(Debug, Clone)]
pub struct DecodedSignal {
    /// The name of the signal as defined in the DBC file
    pub name: String,
    /// The decoded value, either a numeric physical value or an enum label
    pub value: DecodedSignalValue,
    /// The unit of measurement (e.g., "km/h", "°C", "RPM")
    pub unit: String,
}

/// Specifies the IEEE-754 floating-point format for a signal.
///
/// Used internally to properly decode and encode signals that are stored as
/// IEEE-754 floating-point values in CAN messages (via the `SIG_VALTYPE_` DBC field).
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum FloatFormat {
    /// 32-bit IEEE-754 single-precision float (f32)
    F32,
    /// 64-bit IEEE-754 double-precision float (f64)
    F64,
}

impl FloatFormat {
    /// Converts a DBC signal extended value type to a FloatFormat if it's a float type.
    ///
    /// # Arguments
    ///
    /// * `def` - The DBC signal extended value type definition
    ///
    /// # Returns
    ///
    /// Returns `Some(FloatFormat)` if the definition is a float type, or `None`
    /// if it's a signed/unsigned integer type.
    pub fn from_dbc_def(def: can_dbc::SignalExtendedValueType) -> Option<Self> {
        match def {
            can_dbc::SignalExtendedValueType::IEEEfloat32Bit => Some(FloatFormat::F32),
            can_dbc::SignalExtendedValueType::IEEEdouble64bit => Some(FloatFormat::F64),
            can_dbc::SignalExtendedValueType::SignedOrUnsignedInteger => None,
        }
    }

    /// Returns the size of this float format in bits.
    ///
    /// # Returns
    ///
    /// 32 for `F32`, or 64 for `F64`.
    pub fn bit_size(&self) -> usize {
        match self {
            FloatFormat::F32 => 32,
            FloatFormat::F64 => 64,
        }
    }
}

/// Signal metadata for a signal's value interpretation and DBC description/comment.
///
/// Encapsulates optional formatting information for a signal, including
/// enum mappings (for value descriptions) and float format specifications
/// (for IEEE-754 encoded signals).
///
/// Also includes the signal-level description/comment from the DBC, if available.
#[derive(Debug, Clone, Default)]
pub struct SignalMeta {
    /// Maps raw signal values to string enum labels from DBC value descriptions.
    pub enum_map: std::collections::HashMap<i128, String>,

    /// The IEEE-754 float format, if this signal is an IEEE float/double.
    pub float_format: Option<FloatFormat>,

    /// Signal-level description/comment from the DBC.
    pub sig_comment: Option<String>,
}

/// Internal entry representing a loaded CAN message with its format definitions.
///
/// Stores both the base DBC message definition and the signal-specific format
/// metadata (enums and float formats) in a unified structure.
#[derive(Debug, Clone)]
pub struct MsgEntry {
    /// The base DBC message definition containing signals and metadata.
    pub msg_def: can_dbc::Message,
    /// Message-level description/comment from DBC (if available)
    pub msg_desc: Option<String>,
    /// Extra metadata for signals indexed by signal name.
    /// This includes enum mappings for value descriptions and float format info
    /// for IEEE float signals as well as signal-level comments.
    pub signal_meta: std::collections::HashMap<String, SignalMeta>,
}

impl MsgEntry {
    /// Creates a new message entry from a can_dbc message definition.
    ///
    /// # Arguments
    ///
    /// * `msg_def` - The DBC message definition
    ///
    /// # Returns
    ///
    /// A new `MsgEntry` with the message definition, and empty description, and
    /// an empty signal metadata map (to be populated with enums, float formats, and comments).
    fn new(msg_def: can_dbc::Message) -> Self {
        Self {
            msg_def,
            msg_desc: None,
            signal_meta: std::collections::HashMap::new(),
        }
    }
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
#[derive(Debug, Clone)]
pub struct Parser {
    msg_entries: std::collections::HashMap<u32, MsgEntry>,
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
            msg_entries: std::collections::HashMap::new(),
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
    pub fn from_dbc_file(path: &std::path::Path) -> Result<Self, Box<dyn std::error::Error>> {
        let mut parser = Self::new();
        parser.add_from_dbc_file(path)?;
        Ok(parser)
    }

    /// Adds message and enum/value-description definitions from a DBC string.
    ///
    /// This method parses DBC content from a string slice and adds all message
    /// definitions to the parser. If a message ID already exists, it will be
    /// overwritten and a warning will be logged. Signal value descriptions
    /// (enumerations) are also captured for enum decoding. Signal extended
    /// value types (`SIG_VALTYPE_`) are captured for IEEE float/double decoding.
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
    pub fn add_from_str(&mut self, buffer: &str) -> Result<(), Box<dyn std::error::Error>> {
        let dbc = can_dbc::Dbc::try_from(buffer).map_err(|e| {
            log::error!("Failed to parse DBC: {:?}", e);
            format!("{:?}", e)
        })?;

        // Insert message definitions
        for msg_def in dbc.messages {
            let msg_id = msg_def.id.raw();
            if self.msg_entries.contains_key(&msg_id) {
                log::warn!(
                    "Duplicate message ID {msg_id:#X} ({}). Overwriting existing definition.",
                    msg_def.name
                );
            }
            self.msg_entries.insert(msg_id, MsgEntry::new(msg_def));
        }

        // Enum handling
        for val_desc in dbc.value_descriptions {
            let can_dbc::ValueDescription::Signal {
                message_id,
                name,
                value_descriptions,
            } = val_desc
            else {
                continue;
            };

            let msg_id = message_id.raw();

            let Some(msg_entry) = self.msg_entries.get_mut(&msg_id) else {
                log::warn!(
                    "Value description for signal '{}' references unknown message ID {:#X}. \
                    Skipping.",
                    name,
                    msg_id
                );
                continue;
            };

            let enum_def = SignalMeta {
                enum_map: value_descriptions
                    .iter()
                    .map(|vd| (vd.id as i128, vd.description.clone()))
                    .collect(),
                ..Default::default()
            };

            if let Some(existing) = msg_entry.signal_meta.get_mut(&name) {
                existing.enum_map = enum_def.enum_map;

                log::warn!(
                    "Duplicate value description for signal '{}' in message ID {:#X}. \
                    Overwriting existing enum definition.",
                    name,
                    msg_id
                );
            } else {
                msg_entry.signal_meta.insert(name.clone(), enum_def);
            }
        }

        // Float handling
        for sig_ext_val_typ in dbc.signal_extended_value_type_list {
            let Some(float_format) =
                FloatFormat::from_dbc_def(sig_ext_val_typ.signal_extended_value_type)
            else {
                continue;
            };

            let msg_id = sig_ext_val_typ.message_id.raw();
            let signal_name = &sig_ext_val_typ.signal_name;

            let Some(msg_entry) = self.msg_entries.get_mut(&msg_id) else {
                log::warn!(
                    "Float definition for signal '{}' references unknown message ID {:#X}. \
                    Skipping.",
                    signal_name,
                    msg_id
                );
                continue;
            };

            let Some(signal_def) = msg_entry
                .msg_def
                .signals
                .iter()
                .find(|s| s.name == *signal_name)
            else {
                log::warn!(
                    "Float definition for signal '{}' references unknown signal in message ID {:#X}. \
                    Skipping.",
                    signal_name,
                    msg_id
                );
                continue;
            };

            if signal_def.size != float_format.bit_size() as u64 {
                log::warn!(
                    "Signal '{}' in message ID {:#X} marked as {} but size is {} bits. \
                    Skipping float definition.",
                    signal_name,
                    msg_id,
                    match float_format {
                        FloatFormat::F32 => "f32",
                        FloatFormat::F64 => "f64",
                    },
                    signal_def.size
                );
                continue;
            }

            let format_def = SignalMeta {
                float_format: Some(float_format),
                ..Default::default()
            };

            if let Some(existing) = msg_entry.signal_meta.get_mut(signal_name) {
                existing.float_format = format_def.float_format;

                log::warn!(
                    "Duplicate float definition for signal '{}' in message ID {:#X}. \
                    Overwriting existing float definition.",
                    signal_name,
                    msg_id
                );
            } else {
                msg_entry
                    .signal_meta
                    .insert(signal_name.clone(), format_def);
            }
        }

        // Descriptions/comments handling
        for comment in dbc.comments {
            match comment {
                can_dbc::Comment::Message { id, comment } => {
                    let msg_id = id.raw();

                    let Some(msg_entry) = self.msg_entries.get_mut(&msg_id) else {
                        log::warn!("Comment for unknown message ID {:#X}. Skipping.", msg_id);
                        continue;
                    };

                    if msg_entry.msg_desc.is_some() {
                        log::warn!(
                            "Duplicate comment for message ID {:#X}. \
                            Overwriting existing message comment.",
                            msg_id
                        );
                    }

                    msg_entry.msg_desc = Some(comment);
                }
                can_dbc::Comment::Signal {
                    message_id,
                    name,
                    comment,
                } => {
                    let msg_id = message_id.raw();

                    let Some(msg_entry) = self.msg_entries.get_mut(&msg_id) else {
                        log::warn!(
                            "Comment for signal '{}' references unknown message ID {:#X}. Skipping.",
                            name,
                            msg_id
                        );
                        continue;
                    };

                    let signal_meta = msg_entry.signal_meta.entry(name.clone()).or_default();

                    if signal_meta.sig_comment.is_some() {
                        log::warn!(
                            "Duplicate comment for signal '{}' in message ID {:#X}. \
                            Overwriting existing signal comment.",
                            name,
                            msg_id
                        );
                    }

                    signal_meta.sig_comment = Some(comment);
                }
                _ => {}
            }
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
    pub fn add_from_dbc_file(
        &mut self,
        path: &std::path::Path,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let buffer = std::fs::read(path)?;
        let s = String::from_utf8(buffer)?;
        self.add_from_str(&s)?;
        Ok(())
    }

    /// Decodes a raw CAN message into structured data.
    ///
    /// Takes a CAN message ID and raw data bytes, then decodes all signals
    /// according to the DBC definitions. Each signal is extracted, scaled,
    /// and converted to its physical value or enum label (if defined).
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
    ///         println!("  {}: {:?} {}", name, signal.value, signal.unit);
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

        let msg_entry = self.msg_entries.get(&msg_id)?;

        let is_extended = matches!(msg_entry.msg_def.id, can_dbc::MessageId::Extended(_));
        let tx_node = match &msg_entry.msg_def.transmitter {
            can_dbc::Transmitter::NodeName(name) => name.clone(),
            can_dbc::Transmitter::VectorXXX => "Unknown".to_string(),
        };
        let mut decoded_signals = SignalMap::new();

        for signal_def in &msg_entry.msg_def.signals {
            match self.decode_signal(msg_id, signal_def, data) {
                Some(decoded_signal) => {
                    decoded_signals.insert(decoded_signal.name.to_string(), decoded_signal);
                }
                _ => {
                    log::error!(
                        "Failed to decode signal {} from message {}",
                        signal_def.name,
                        msg_entry.msg_def.name
                    );
                    return None;
                }
            }
        }

        Some(DecodedMessage {
            name: msg_entry.msg_def.name.clone(),
            msg_id,
            is_extended,
            tx_node,
            signals: decoded_signals,
        })
    }

    /// Decodes a single signal from raw CAN data.
    ///
    /// Extracts the raw bits for a signal, converts to signed/unsigned as needed,
    /// and then either resolves a DBC enum label or applies scaling/offset to
    /// produce a numeric physical value. If `SIG_VALTYPE_` marks the signal as
    /// IEEE float/double, raw bits are interpreted directly as `f32`/`f64`.
    fn decode_signal(
        &self,
        msg_id: u32,
        signal_def: &can_dbc::Signal,
        data: &[u8],
    ) -> Option<DecodedSignal> {
        // Extract raw value based on byte order and signal properties
        let raw_value = self.extract_signal_value(
            data,
            signal_def.start_bit as usize,
            signal_def.size as usize,
            signal_def.byte_order,
        )?;

        // Convert to signed if needed
        let raw_value_with_sign: i128 = if signal_def.value_type == can_dbc::ValueType::Signed {
            let shift = 128u32.saturating_sub(signal_def.size as u32);
            ((raw_value as i128) << shift) >> shift
        } else {
            raw_value as i128
        };

        // Check if this signal has an enum definition
        let format_def = self
            .msg_entries
            .get(&msg_id)
            .and_then(|entry| entry.signal_meta.get(&signal_def.name));
        if let Some(format_def) = format_def {
            if let Some(enum_str) = format_def.enum_map.get(&raw_value_with_sign) {
                let physical = raw_value_with_sign as f64 * signal_def.factor + signal_def.offset;
                return Some(DecodedSignal {
                    name: signal_def.name.clone(),
                    value: DecodedSignalValue::new_enum(
                        physical,
                        raw_value_with_sign,
                        enum_str.clone(),
                    ),
                    unit: signal_def.unit.clone(),
                });
            } else {
                log::warn!(
                    "Raw value {} for signal '{}' in message ID {:#X} does not have a corresponding enum label. \
                    Returning raw value as numeric.",
                    raw_value_with_sign,
                    signal_def.name,
                    msg_id
                );
            }
        }

        // Check for float definition
        let float_def = self
            .msg_entries
            .get(&msg_id)
            .and_then(|entry| entry.signal_meta.get(&signal_def.name))
            .and_then(|format_def| format_def.float_format);
        if let Some(float_format) = float_def {
            // Note: signal sizes are validated when loading the DBC, so we can assume 32 bits for f32 and 64 bits for f64
            let float_value = match float_format {
                FloatFormat::F32 => f32::from_bits(raw_value as u32) as f64,
                FloatFormat::F64 => f64::from_bits(raw_value),
            };
            let scaled_value = float_value * signal_def.factor + signal_def.offset;
            return Some(DecodedSignal {
                name: signal_def.name.clone(),
                value: DecodedSignalValue::new_float_backed_numeric(scaled_value),
                unit: signal_def.unit.clone(),
            });
        }

        // Not enum or float, signed/unsigned integer
        let scaled_value = raw_value_with_sign as f64 * signal_def.factor + signal_def.offset;
        Some(DecodedSignal {
            name: signal_def.name.clone(),
            value: DecodedSignalValue::new_integer_backed_numeric(
                scaled_value,
                raw_value_with_sign,
            ),
            unit: signal_def.unit.clone(),
        })
    }

    /// Extracts raw signal bits from CAN data.
    ///
    /// This function reads the raw bits for a signal from the CAN message data,
    /// handling both little-endian and big-endian byte ordering according to DBC specifications.
    ///
    /// ## Little-Endian Extraction
    ///
    /// For little-endian signals, bits are read starting from `start_bit` and proceeding
    /// through sequential bytes, with results accumulated in the LSB-first order.
    ///
    /// ## Big-Endian Extraction
    ///
    /// For big-endian signals, `start_bit` specifies the MSB position using DBC's sawtooth numbering.
    /// The bits are extracted MSB-first and accumulated into the result.
    ///
    /// # Arguments
    ///
    /// * `data` - The raw CAN message bytes
    /// * `start_bit` - Starting bit position (DBC-style)
    /// * `size` - Number of bits to extract
    /// * `byte_order` - Byte order (little-endian or big-endian)
    ///
    /// # Returns
    ///
    /// The extracted bits as a `u64`, or `None` if data is empty or out of bounds.
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

        let mut result = 0u64;

        match byte_order {
            can_dbc::ByteOrder::LittleEndian => {
                // For little-endian, start_bit gives us the LSB position
                let start_byte = start_bit / 8;
                let start_bit_in_byte = start_bit % 8;

                let mut remaining_bits = size;
                let mut current_byte = start_byte;
                let mut bit_offset = start_bit_in_byte;

                // Read bits sequentially across bytes
                while remaining_bits > 0 {
                    if current_byte >= data.len() {
                        // Out of bounds: cannot extract signal
                        return None;
                    }

                    // Determine how many bits we can read from this byte
                    let bits_in_this_byte = std::cmp::min(remaining_bits, 8 - bit_offset);
                    // Create mask for the bits we want from this byte
                    let mask = low_bits_mask!(bits_in_this_byte, u64) << bit_offset;
                    // Extract and shift the bits to the LSB position
                    let byte_value = ((data[current_byte] as u64) & mask) >> bit_offset;

                    // Place the extracted bits in the result, with higher-order bits on the left
                    result |= byte_value << (size - remaining_bits);

                    remaining_bits -= bits_in_this_byte;
                    current_byte += 1;
                    bit_offset = 0;
                }
            }
            can_dbc::ByteOrder::BigEndian => {
                // For big-endian (Motorola), start_bit specifies the MSB position.
                // The DBC "sawtooth" numbering:
                //   - byte_idx = start_bit / 8
                //   - bit_in_byte = start_bit % 8 (0=LSB, 7=MSB of the byte)

                let start_byte = start_bit / 8;
                let start_bit_in_byte = start_bit % 8; // Physical bit index (0-7)

                let mut byte_idx = start_byte;
                let mut bit_in_byte = start_bit_in_byte as i32; // Current bit position, counts downward

                // Extract bits from MSB to LSB
                for _i in 0..size {
                    if byte_idx >= data.len() {
                        // Out of bounds: cannot extract signal
                        return None;
                    }

                    // Extract one bit at the current position
                    let bit_val = (data[byte_idx] >> bit_in_byte) & 1;
                    // Shift result left and add the extracted bit
                    result = (result << 1) | (bit_val as u64);

                    // Move to the next bit (downward within the byte)
                    bit_in_byte -= 1;
                    // If we've gone past bit 0, move to the next byte
                    if bit_in_byte < 0 {
                        bit_in_byte = 7;
                        byte_idx += 1;
                    }
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
    /// the signal's byte order and position.
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
        let msg_entry = self.msg_entries.get(&msg_id)?;

        let msg_size = msg_entry.msg_def.size as usize;
        let mut data = vec![0u8; msg_size];

        for signal_def in &msg_entry.msg_def.signals {
            let physical_value = match signal_values.get(&signal_def.name) {
                Some(&v) => v,
                _ => {
                    log::error!(
                        "Signal {} not provided for message {} during encoding",
                        signal_def.name,
                        msg_entry.msg_def.name
                    );
                    return None;
                }
            };

            // encode_signal() modifies the data buffer in place
            if self
                .encode_signal(msg_id, signal_def, physical_value, &mut data)
                .is_none()
            {
                log::error!(
                    "Failed to encode signal {} for message {}",
                    signal_def.name,
                    msg_entry.msg_def.name
                );
                return None;
            }
        }

        Some(data)
    }

    /// Encodes a CAN message by message name instead of ID.
    ///
    /// Looks up the message by name and then encodes it. This is slower as it
    /// requires searching through all loaded messages.
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
        let (msg_id, _msg_entry) = self
            .msg_entries
            .iter()
            .find(|(_id, entry)| entry.msg_def.name == msg_name)?;

        let data = self.encode_msg(*msg_id, signal_values)?;
        Some((*msg_id, data))
    }

    /// Encodes a single signal into raw CAN data.
    ///
    /// Converts a physical signal value back to its raw representation by:
    /// 1. Applying inverse scaling: `raw_value = (physical_value - offset) / factor`
    /// 2. Converting to the appropriate integer representation (signed/unsigned)
    /// 3. Clamping to the valid range for the signal's bit width
    /// 4. Packing the bits into the data buffer at the signal's bit position
    ///
    /// For IEEE float/double signals, the physical value is converted directly
    /// to f32 or f64 and the bit pattern is extracted.
    ///
    /// # Arguments
    ///
    /// * `msg_id` - The CAN message ID (used to look up format definitions)
    /// * `signal_def` - The DBC signal definition
    /// * `physical_value` - The physical value to encode
    /// * `data` - Mutable buffer to write the encoded bits into
    ///
    /// # Returns
    ///
    /// `Some(())` on success, `None` if encoding fails (e.g., bounds check)
    fn encode_signal(
        &self,
        msg_id: u32,
        signal_def: &can_dbc::Signal,
        physical_value: f64,
        data: &mut [u8],
    ) -> Option<()> {
        // Apply inverse scaling to convert physical value back to raw value
        let scaled_value = (physical_value - signal_def.offset) / signal_def.factor;

        // Check if this is an IEEE float/double signal
        let float_def = self
            .msg_entries
            .get(&msg_id)
            .and_then(|entry| entry.signal_meta.get(&signal_def.name))
            .and_then(|format_def| format_def.float_format);
        if let Some(float_format) = float_def {
            // For float signals, convert to the appropriate float type and extract bit pattern
            let float_data = match float_format {
                FloatFormat::F32 => (scaled_value as f32).to_bits() as u64,
                FloatFormat::F64 => scaled_value.to_bits(),
            };
            return self.insert_signal_value(
                data,
                signal_def.start_bit as usize,
                signal_def.size as usize,
                signal_def.byte_order,
                float_data,
            );
        }

        // For integer signals, convert and handle signed/unsigned representation
        let raw_int = if signal_def.value_type == can_dbc::ValueType::Signed {
            let signed_val = scaled_value.round() as i64;
            // Use i128 to avoid overflow when size==64
            let max_value = ((1i128 << (signal_def.size - 1)) - 1) as i64;
            let min_value = -(1i128 << (signal_def.size - 1)) as i64;

            let clamped = signed_val.max(min_value).min(max_value);

            // Two's complement: negative values cast to u64 already gives correct bit pattern
            let mask = low_bits_mask!(signal_def.size as usize, u64);
            (clamped as u64) & mask
        } else {
            let unsigned_val = scaled_value.round() as u64;
            let max_value = low_bits_mask!(signal_def.size as usize, u64);
            unsigned_val.min(max_value)
        };

        // Insert the encoded bits into the data buffer
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
    /// This function packs raw bits (typically from encoding) into the CAN message buffer,
    /// handling both little-endian and big-endian byte ordering.
    ///
    /// ## Little-Endian Insertion
    ///
    /// For little-endian signals, bits are packed starting from `start_bit` across sequential
    /// bytes, with the LSBs of the value written first.
    ///
    /// ## Big-Endian Insertion
    ///
    /// For big-endian signals, `start_bit` specifies the MSB position using DBC's sawtooth numbering.
    /// Bits are packed from MSB to LSB starting at that position.
    ///
    /// # Arguments
    ///
    /// * `data` - Mutable buffer of CAN message bytes to modify
    /// * `start_bit` - Starting bit position (DBC-style)
    /// * `size` - Number of bits to insert
    /// * `byte_order` - Byte order (little-endian or big-endian)
    /// * `value` - The raw value to insert
    ///
    /// # Returns
    ///
    /// `Some(())` on success, or `None` if the signal extends beyond the data bounds.
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
            // Signal extends beyond the data buffer
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

                // Write bits sequentially across bytes
                while remaining_bits > 0 && current_byte < data.len() {
                    // Determine how many bits we can write to this byte
                    let bits_in_this_byte = std::cmp::min(remaining_bits, 8 - bit_offset);
                    // Create a mask for the bits we're about to write
                    let mask = low_bits_mask!(bits_in_this_byte, u8) << bit_offset;

                    // Extract the bits we want from the value
                    let value_mask = low_bits_mask!(bits_in_this_byte, u64);
                    let value_bits = ((value >> value_offset) & value_mask) as u8;

                    // Clear the target bits in the data byte and set new bits
                    data[current_byte] =
                        (data[current_byte] & !mask) | ((value_bits << bit_offset) & mask);

                    remaining_bits -= bits_in_this_byte;
                    value_offset += bits_in_this_byte;
                    current_byte += 1;
                    bit_offset = 0;
                }
            }
            can_dbc::ByteOrder::BigEndian => {
                let start_byte = start_bit / 8;
                let start_bit_in_byte = start_bit % 8;

                let mut byte_idx = start_byte;
                let mut bit_in_byte = start_bit_in_byte as i32;

                // Write bits from MSB to LSB
                for i in 0..size {
                    if byte_idx >= data.len() {
                        return None;
                    }

                    // Extract the i-th bit from the value (starting from MSB)
                    let bit_val = ((value >> (size - 1 - i)) & 1) as u8;
                    // Create a mask for the target bit position
                    let mask = 1u8 << bit_in_byte;
                    // Clear the bit and set the new value
                    data[byte_idx] = (data[byte_idx] & !mask) | (bit_val << bit_in_byte);

                    // Move to the next bit (downward within the byte)
                    bit_in_byte -= 1;
                    // If we've gone past bit 0, move to the next byte
                    if bit_in_byte < 0 {
                        bit_in_byte = 7;
                        byte_idx += 1;
                    }
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
        let msg_entry = self.msg_entries.get(&msg_id)?;
        Some(msg_entry.msg_def.signals.clone())
    }

    /// Returns the message-level description/comment for a message ID.
    ///
    /// # Returns
    ///
    /// A reference to the message comment if present, or `None` if the message
    /// is unknown or has no DBC comment.
    pub fn msg_desc(&self, msg_id: u32) -> Option<&str> {
        self.msg_entries
            .get(&msg_id)
            .and_then(|entry| entry.msg_desc.as_deref())
    }

    /// Returns the signal-level description/comment for a signal within a message.
    ///
    /// # Returns
    ///
    /// A reference to the signal comment if present, or `None` if the message,
    /// signal, or comment is not available.
    pub fn signal_desc(&self, msg_id: u32, signal_name: &str) -> Option<&str> {
        self.msg_entries
            .get(&msg_id)
            .and_then(|entry| entry.signal_meta.get(signal_name))
            .and_then(|meta| meta.sig_comment.as_deref())
    }

    /// Returns all loaded can_dbc message definitions.
    ///
    /// # Returns
    ///
    /// A vector containing all message definitions that have been loaded
    /// from DBC files. O(n) to convert from internal map.
    pub fn msg_defs(&self) -> Vec<can_dbc::Message> {
        self.msg_entries
            .values()
            .map(|entry| entry.msg_def.clone())
            .collect()
    }

    /// Returns the can_dbc message definition for a given message ID. O(1) lookup.
    ///
    /// # Arguments
    ///
    /// * `msg_id` - The CAN message identifier
    ///
    /// # Returns
    ///
    /// Returns a reference to the message definition if found, or `None` if
    /// the message ID is not known.
    pub fn msg_def(&self, msg_id: u32) -> Option<&can_dbc::Message> {
        self.msg_entries.get(&msg_id).map(|entry| &entry.msg_def)
    }

    /// Exposes the internal message entries map.
    ///
    /// This provides access to all loaded messages indexed by their CAN message IDs,
    /// including their format definitions (enums and float types).
    ///
    /// # Returns
    ///
    /// A reference to the HashMap mapping message IDs to `MsgEntry` structures.
    /// Each `MsgEntry` contains both the DBC message definition and its associated
    /// format metadata.
    pub fn msg_entries(&self) -> &std::collections::HashMap<u32, MsgEntry> {
        &self.msg_entries
    }

    /// Returns the message entry for a given message ID. O(1) lookup.
    ///
    /// Provides access to both the DBC message definition and its format definitions
    /// (enums and float type specifications) for a specific message ID.
    ///
    /// # Arguments
    ///
    /// * `msg_id` - The CAN message identifier
    ///
    /// # Returns
    ///
    /// Returns a reference to the `MsgEntry` if found, or `None` if the message ID
    /// is not known. The `MsgEntry` contains both `msg_def` (the DBC definition) and
    /// `format_defs` (the signal formatting metadata).
    pub fn msg_entry(&self, msg_id: u32) -> Option<&MsgEntry> {
        self.msg_entries.get(&msg_id)
    }

    /// Clears all loaded message definitions.
    ///
    /// After calling this method, the parser will have no message definitions
    /// or signal mappings (enum/value-description and float type mappings).
    ///
    /// # Example
    ///
    /// ```
    /// use can_decode::Parser;
    ///
    /// let mut parser = Parser::new();
    /// // Load some DBC files or add definitions...
    /// parser.clear();
    /// ```
    pub fn clear(&mut self) {
        self.msg_entries.clear();
    }
}

impl Default for Parser {
    fn default() -> Self {
        Self::new()
    }
}
