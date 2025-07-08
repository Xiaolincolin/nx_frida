function hook_h_x8() {
    const base = Module.findBaseAddress("libyaqpro.3e364a2a.so"); // 替换为你的 so 文件名
    // const addr_set_x8 = base.add(0x29DC8);  // LDR X8, [X9,#0x370]
    const addr_blr_x8 = base.add(0x4AF70);  // BLR X8

    console.log("[*] Base address of lib: " + base);
    console.log("[*] Hooking BLR X8 at: " + addr_blr_x8);

// Step 1: Hook LDR X8 处，观察 X9 → X8 的传递
//     Interceptor.attach(addr_set_x8, {
//         onEnter(args) {
//             const ctx = this.context;
//             console.log("=== [Step 1] Setting X8 ===");
//             console.log("X9:", ptr(ctx.x9));
//             console.log("Reading [X9 + 0x370] =", Memory.readPointer(ptr(ctx.x9).add(0x370)));
//             console.log("X26:", ptr(ctx.x26));
//             console.log("X20:", ptr(ctx.x20));
//         }
//     });

// Step 2: Hook BLR X8，观察调用目标
    Interceptor.attach(addr_blr_x8, {
        onEnter(args) {
            const ctx = this.context;
            console.log("=== [Step 2] Calling BLR X8 ===");
            console.log("X0 (arg0):", hexdump(ctx.x0));

            let x8_addr = ptr(ctx.x8)
            console.log("X8 (target):",x8_addr ,'offset:',x8_addr.sub(base));
            try {
                const sym = DebugSymbol.fromAddress(ptr(ctx.x8));
                console.log("Symbol:", sym.name, "| Module:", sym.moduleName);
            } catch (e) {
                console.log("Symbol: (unknown)");
            }
        },
        onLeave(retval) {
            console.log("=== Return value:", retval);
        }
    });

}


setImmediate(hook_h_x8);
