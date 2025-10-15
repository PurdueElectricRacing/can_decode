# can_decode

Decode / parse CAN frames into messages/signals in a fast and easy way.

[![Crates.io](https://img.shields.io/crates/v/can_decode.svg)](https://crates.io/crates/can_decode)
[![Docs.rs](https://docs.rs/can_decode/badge.svg)](https://docs.rs/can_decode)

## Features

- Parse DBC (CAN Database) files
- Decode CAN messages into signals with physical values
- Support for both standard and extended CAN IDs
- Handle big-endian and little-endian byte ordering
- Support for signed and unsigned signal values
- Apply scaling factors and offsets

## Example

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
