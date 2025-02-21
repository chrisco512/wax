const std = @import("std");

// VM hooks for Stylus runtime
pub extern "vm_hooks" fn account_balance(address: *const u8, dest: *u8) void;
pub extern "vm_hooks" fn account_code(address: *const u8, offset: usize, size: usize, dest: *u8) usize;
pub extern "vm_hooks" fn account_code_size(address: *const u8) usize;
pub extern "vm_hooks" fn account_codehash(address: *const u8, dest: *u8) void;
pub extern "vm_hooks" fn storage_load_bytes32(key: *const u8, dest: *u8) void;
pub extern "vm_hooks" fn storage_cache_bytes32(key: *const u8, value: *const u8) void;
pub extern "vm_hooks" fn storage_flush_cache(clear: bool) void;
pub extern "vm_hooks" fn block_basefee(basefee: *u8) void;
pub extern "vm_hooks" fn chainid() u64;
pub extern "vm_hooks" fn block_coinbase(coinbase: *u8) void;
pub extern "vm_hooks" fn block_gas_limit() u64;
pub extern "vm_hooks" fn block_number() u64;
pub extern "vm_hooks" fn block_timestamp() u64;
pub extern "vm_hooks" fn call_contract(
    contract: *const u8,
    calldata: *const u8,
    calldata_len: usize,
    value: *const u8,
    gas: u64,
    return_data_len: *usize,
) u8;
pub extern "vm_hooks" fn contract_address(address: *u8) void;
pub extern "vm_hooks" fn create1(
    code: *const u8,
    code_len: usize,
    endowment: *const u8,
    contract: *u8,
    revert_data_len: *usize,
) void;
pub extern "vm_hooks" fn create2(
    code: *const u8,
    code_len: usize,
    endowment: *const u8,
    salt: *const u8,
    contract: *u8,
    revert_data_len: *usize,
) void;
pub extern "vm_hooks" fn delegate_call_contract(
    contract: *const u8,
    calldata: *const u8,
    calldata_len: usize,
    gas: u64,
    return_data_len: *usize,
) u8;
pub extern "vm_hooks" fn emit_log(data: *const u8, len: usize, topics: usize) void;
pub extern "vm_hooks" fn evm_gas_left() u64;
pub extern "vm_hooks" fn evm_ink_left() u64;
pub extern "vm_hooks" fn pay_for_memory_grow(pages: u16) void;
pub extern "vm_hooks" fn msg_reentrant() bool;
pub extern "vm_hooks" fn msg_sender(sender: *u8) void;
pub extern "vm_hooks" fn msg_value(value: *u8) void;
pub extern "vm_hooks" fn native_keccak256(bytes: *const u8, len: usize, output: *u8) void;
pub extern "vm_hooks" fn read_args(dest: *u8) void;
pub extern "vm_hooks" fn read_return_data(dest: *u8, offset: usize, size: usize) usize;
pub extern "vm_hooks" fn write_result(data: *const u8, len: usize) void;
pub extern "vm_hooks" fn return_data_size() usize;
pub extern "vm_hooks" fn static_call_contract(
    contract: *const u8,
    calldata: *const u8,
    calldata_len: usize,
    gas: u64,
    return_data_len: *usize,
) u8;
pub extern "vm_hooks" fn tx_gas_price(gas_price: *u8) void;
pub extern "vm_hooks" fn tx_ink_price() u32;
pub extern "vm_hooks" fn tx_origin(origin: *u8) void;
