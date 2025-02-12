# stylus-zig-erc20
A zig stylus program of ERC20 token

## build
```bash
zig build-exe ./src/main.zig -target wasm32-freestanding -fno-entry --export=user_entrypoint -OReleaseSmall --export=user_entrypoint
```
zig version: 0.13.0