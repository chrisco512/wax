const std = @import("std");

pub extern "vm_hooks" fn pay_for_memory_grow(len: u32) void;

pub const ArbitrumWasmAllocator = struct {
    /// Tracks the current number of 64KB pages allocated
    pages_allocated: u32 = 0,

    /// Inner allocator (raw WASM allocator without hooks)
    inner: std.mem.Allocator = std.heap.wasm_allocator,

    pub fn allocator(self: *ArbitrumWasmAllocator) std.mem.Allocator {
        return .{
            .ptr = self,
            .vtable = &.{
                .alloc = alloc,
                .resize = resize,
                .free = free,
            },
        };
    }

    fn alloc(ctx: *anyopaque, len: usize, ptr_align: u8, _: usize) ?[*]u8 {
        const self = @as(*ArbitrumWasmAllocator, @ptrCast(ctx));
        const page_size = 65536; // WASM page size is 64KB
        const requested_pages = @as(u32, @intCast((len + page_size - 1) / page_size)); // Ceiling division

        // If we need more pages than currently allocated
        if (requested_pages > self.pages_allocated) {
            const additional_pages = requested_pages - self.pages_allocated;
            pay_for_memory_grow(additional_pages); // Request only the additional pages
            self.pages_allocated = requested_pages; // Update tracking
        }

        // Delegate to the raw WASM allocator
        return self.inner.rawAlloc(len, ptr_align, 0);
    }

    fn resize(ctx: *anyopaque, buf: []u8, buf_align: u8, new_len: usize, _: usize) bool {
        const self = @as(*ArbitrumWasmAllocator, @ptrCast(ctx));
        const page_size = 65536;
        const requested_pages = @as(u32, @intCast((new_len + page_size - 1) / page_size));

        // If resizing requires more pages
        if (requested_pages > self.pages_allocated) {
            const additional_pages = requested_pages - self.pages_allocated;
            pay_for_memory_grow(additional_pages);
            self.pages_allocated = requested_pages;
        }

        // Delegate resizing; if shrinking, we don’t reduce pages_allocated (conservative)
        return self.inner.rawResize(buf, buf_align, new_len, 0);
    }

    fn free(ctx: *anyopaque, buf: []u8, buf_align: u8, _: usize) void {
        const self = @as(*ArbitrumWasmAllocator, @ptrCast(ctx));
        self.inner.rawFree(buf, buf_align, 0);
        // Note: We don’t decrease pages_allocated here, as WASM memory doesn’t shrink
    }
};

// Global instance of the custom allocator
var arbitrum_wasm_allocator_instance = ArbitrumWasmAllocator{};
pub const arbitrum_wasm_allocator = arbitrum_wasm_allocator_instance.allocator();
