pub type IdType = u32;

#[derive(Debug, Clone)]
pub struct DecodedMessage {
    pub name: String,
    pub msg_id: IdType,
    pub is_extended: bool,
    pub signals: std::collections::HashMap<String, DecodedSignal>,
}

#[derive(Debug, Clone)]
pub struct DecodedSignal {
    pub name: String,
    pub value: f64,
    pub unit: String,
}

pub struct Parser {
    message_defs: std::collections::HashMap<IdType, can_dbc::Message>,
}

impl Parser {
    pub fn new() -> Self {
        Self {
            message_defs: std::collections::HashMap::new(),
        }
    }

    pub fn add_from_slice(&mut self, buffer: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        let dbc = can_dbc::DBC::from_slice(buffer).map_err(|e| {
            log::error!("Failed to parse DBC: {:?}", e);
            format!("{:?}", e)
        })?;
        for message in dbc.messages() {
            let msg_id = match message.message_id() {
                can_dbc::MessageId::Standard(id) => *id as u32,
                can_dbc::MessageId::Extended(id) => *id,
            };
            if self.message_defs.contains_key(&msg_id) {
                log::warn!(
                    "Duplicate message ID {msg_id:#X} ({}). Overwriting existing definition.",
                    message.message_name()
                );
            }
            self.message_defs.insert(msg_id, message.clone());
        }
        Ok(())
    }

    pub fn add_from_dbc_file(
        &mut self,
        path: &std::path::Path,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut f = std::fs::File::open(path)?;
        let mut buffer = Vec::new();
        std::io::Read::read_to_end(&mut f, &mut buffer)?;
        self.add_from_slice(&buffer)
            .map_err(|e| format!("{:?}", e))?;
        Ok(())
    }

    pub fn decode_msg(&self, msg_id: IdType, data: &[u8]) -> Option<DecodedMessage> {
        // Grab msg metadata and then for every signal in the message, decode it and add
        // to the decoded message
        let msg_def = self.message_defs.get(&msg_id)?;
        let msg_name = msg_def.message_name().to_string();
        let is_extended = matches!(msg_def.message_id(), can_dbc::MessageId::Extended(_));
        let mut decoded_signals = std::collections::HashMap::new();

        for signal_def in msg_def.signals() {
            match self.decode_signal(signal_def, data) {
                Some(decoded_signal) => {
                    decoded_signals.insert(decoded_signal.name.to_string(), decoded_signal);
                }
                None => {
                    log::warn!(
                        "Failed to decode signal {} from message {}",
                        signal_def.name(),
                        msg_name
                    );
                }
            }
        }

        Some(DecodedMessage {
            name: msg_name,
            msg_id,
            is_extended,
            signals: decoded_signals,
        })
    }

    fn decode_signal(&self, signal_def: &can_dbc::Signal, data: &[u8]) -> Option<DecodedSignal> {
        // Get signal properties
        let start_bit = *signal_def.start_bit() as usize;
        let signal_size = *signal_def.signal_size() as usize;
        let byte_order = signal_def.byte_order();
        let value_type = signal_def.value_type();
        let factor = signal_def.factor();
        let offset = signal_def.offset();
        let unit = signal_def.unit();

        // Extract raw value based on byte order and signal properties
        let raw_value = self.extract_signal_value(data, start_bit, signal_size, *byte_order)?;

        // Convert to signed if needed
        let raw_value = if *value_type == can_dbc::ValueType::Signed {
            // Convert to signed based on signal size
            let max_unsigned = (1u64 << signal_size) - 1;
            let sign_bit = 1u64 << (signal_size - 1);

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
        let scaled_value = raw_value * factor + offset;

        Some(DecodedSignal {
            name: signal_def.name().to_string(),
            value: scaled_value,
            unit: unit.to_string(),
        })
    }

    fn extract_signal_value(
        &self,
        data: &[u8],
        start_bit: usize,
        size: usize,
        byte_order: can_dbc::ByteOrder,
    ) -> Option<u64> {
        if data.len() < 8 {
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
                    let byte_value = (data[current_byte] as u64 & mask) >> bit_offset;

                    result |= byte_value << (size - remaining_bits);

                    remaining_bits -= bits_in_this_byte;
                    current_byte += 1;
                    bit_offset = 0;
                }
            }
            can_dbc::ByteOrder::BigEndian => {
                // Idk if this is right
                let mut bit_pos = start_bit;

                for _ in 0..size {
                    let byte_idx = bit_pos / 8;
                    let bit_idx = 7 - (bit_pos % 8); // MSB first

                    if byte_idx < data.len() {
                        let bit_val = (data[byte_idx] >> bit_idx) & 1;
                        result = (result << 1) | (bit_val as u64);
                    }

                    bit_pos += 1;
                }
            }
        }

        Some(result)
    }

    pub fn signals_for_msg(&self, msg_id: IdType) -> Option<Vec<can_dbc::Signal>> {
        let msg_def = self.message_defs.get(&msg_id)?;
        Some(msg_def.signals().to_vec())
    }
}

impl Default for Parser {
    fn default() -> Self {
        Self::new()
    }
}
