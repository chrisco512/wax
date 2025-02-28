# Wax
A simple, zero-dependency smart contract framework for Arbitrum Stylus, written in Zig

## Philosophy

- Simple router-based app framework
- Supports middleware
- Tiny binaries
- Maximum performance
- Learn it in an afternoon (even with zero Zig experience)
- Avoid esoteric language features wherever possible
- Stick with basic building blocks as much as possible: functions, structs, arrays, enums
- Easily testable

## Dependencies

This code is running on a pre-release of Zig 0.14 (which is due in next couple of weeks). Install Zig from master, see: https://ziglang.org/download/. 

You'll also need Arbitrum Nitro dev node to test, which depends on Docker. See: https://docs.arbitrum.io/run-arbitrum-node/run-nitro-dev-node

In addition, you'll need cargo stylus to deploy: https://github.com/OffchainLabs/cargo-stylus

## Running Examples

After all dependencies are installed. Make sure you have Arbitrum Nitro Dev node running locally by following instructions from link above.

Navigate to examples/counter and run `zig build`. It will produce a `main.wasm` file in `examples/counter/zig-out/bin`. Navigate to that directory and then run:

```bash
> RPC=http://localhost:8547
> PRIVATE_KEY=0xb6b15c8cb491557369f3c7d2c287b053eb229daa9c22138887752191c9520659
> cargo stylus deploy --no-verify --endpoint $RPC --private-key $PRIVATE_KEY --wasm-file=main.wasm
```

## Notice

This code is still in early-stage development and should not be used in production.
