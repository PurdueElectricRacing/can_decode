# can_decode

Decode / parse CAN frames into messages/signals in a fast and easy way.

<!-- [![Crates.io](https://img.shields.io/crates/v/can_decode.svg)](https://crates.io/crates/can_decode)
[![Docs.rs](https://docs.rs/can_decode/badge.svg)](https://docs.rs/can_decode) -->

## Example

```rust
fn main() {
    env_logger::init();

    let parser = match can_decode::Parser::from_dbc_file(&args.vcan_dbc) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Error parsing DBC file: {}", e);
            std::process::exit(1);
        }
    };

	let arb_id = 0x123;
	let data = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
	let decoded = parser.decode_msg(arb_id, &data);
	match decoded {
		Some(msg) => {
			println!("Decoded message: {:?}", msg);
		}
		None => {
			println!("No message found for arb_id: {:#X}", arb_id);
		}
	}
}
```
