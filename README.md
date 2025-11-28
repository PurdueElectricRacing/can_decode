# can_decode

Decode and encode CAN frames into messages/signals in a fast and easy way.

[![Crates.io](https://img.shields.io/crates/v/can_decode.svg)](https://crates.io/crates/can_decode)
[![Docs.rs](https://docs.rs/can_decode/badge.svg)](https://docs.rs/can_decode)

## Features

- Parse DBC (CAN Database) files
- Decode CAN messages into signals with physical values
- Encode signal values back into raw CAN messages
- Support for both standard and extended CAN IDs
- Handle big-endian and little-endian byte ordering
- Support for signed and unsigned signal values
- Apply scaling factors and offsets (and inverse for encoding)

## Decoding Example

```rust
use can_decode::Parser;
use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
	// Load a DBC file
	let parser = Parser::from_dbc_file(Path::new("my_can_database.dbc"))?;

	// Decode a CAN message
	let msg_id = 0x123;
	let data = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];

	if let Some(decoded) = parser.decode_msg(msg_id, &data) {
		println!("Message: {}", decoded.name);
		for (signal_name, signal) in &decoded.signals {
			println!("  {}: {} {}", signal_name, signal.value, signal.unit);
		}
	}
	Ok(())
}
```

## Encoding Example

```rust
use can_decode::Parser;
use std::path::Path;
use std::collections::HashMap;

fn main() -> Result<(), Box<dyn std::error::Error>> {
	let parser = Parser::from_dbc_file(Path::new("my_can_database.dbc"))?;

	// Encode a CAN message from signal values
	let mut signal_values = HashMap::from([
		("EngineSpeed".to_string(), 2500.0),
		("ThrottlePosition".to_string(), 45.5),
	]);

	if let Some(data) = parser.encode_msg(0x123, &signal_values) {
		println!("Encoded CAN data: {:02X?}", data);
	}

	// Or encode by message name
	if let Some((msg_id, data)) = parser.encode_msg_by_name("EngineData", &signal_values) {
		println!("Message ID: {:#X}, Data: {:02X?}", msg_id, data);
	}
	Ok(())
}
````

## Installation

Add the following to your `Cargo.toml`:

```toml
[dependencies]
can_decode = "0.4"
```
