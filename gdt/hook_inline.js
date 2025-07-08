let libName = "libgdtqone.so"


function hook_inline_1() {
    const base = Module.findBaseAddress(libName);
    if (!base) {
        console.log('not found base')
        return
    }

    // 替换为你自己的地址
    const sub_AF08_ptr = base.add(0xAF08);
    const sub_17F2C_ptr = base.add(0x17F2C);
    const sub_1AFD0_ptr = base.add(0x1AFD0);
    const sub_B3A8_addr = base.add(0xB3A8);

// 保存最近一个字符串（可能是 key 或 value）
    let lastString = null;

    Interceptor.attach(sub_AF08_ptr, {
        onEnter(args) {
            const strPtr = args[1];
            try {
                const s = strPtr.readUtf8String();
                lastString = s;
                console.log(`[sub_AF08] preparing string: "${s}"`);
            } catch (e) {
                lastString = null;
            }
        }
    });

    Interceptor.attach(sub_17F2C_ptr, {
        onEnter(args) {
            const a2 = args[1];
            let valueStr = '(unreadable)';
            try {
                const flag = a2.readU8(); // 第一字节可能是 flag
                if ((flag & 1) === 0) {
                    // 低位为 0，表示内联字符串，读取 a2 + 0x10
                    const strPtr = a2.add(0x10);
                    valueStr = strPtr.readUtf8String();
                } else {
                    // 高位为 1，表示堆分配，指针在 a2 + 0x10
                    const heapPtr = a2.add(0x10).readPointer();
                    valueStr = heapPtr.readUtf8String();
                }
            } catch (e) {
                valueStr = `(error reading: ${e})`;
            }
            console.log(`[sub_17F2C] a2 @ ${a2} → value: "${valueStr}"`);
        }
    });

    Interceptor.attach(sub_1AFD0_ptr, {
        onEnter(args) {

        }, onLeave(retval) {
            const out = this.context.x0;  // 或 args[1]
            const tag = Memory.readU64(out);
            let ptr, len;
            if ((tag & 1) === 0) {
                len = tag >>> 1;
                ptr = out.add(8);
            } else {
                len = Memory.readU64(out.add(8));
                ptr = Memory.readPointer(out.add(16));
            }
            try {
                const str = Memory.readUtf8String(ptr);  // 不给 len，Frida 自动遇 0 终止
                console.log("Partial string:", str);
            } catch (e) {
                console.warn("Invalid UTF-8 at offset", e.offset || "?");
            }
        }
    });

    Interceptor.attach(sub_B3A8_addr, {
        onEnter(args) {
            console.log('enter sub_B3A8')
            this.result = args[0];
            this.a2 = args[1];
        },
        onLeave(retval) {

            try {
                const result = this.result;
                const flag = result.readU8();
                let strPtr, length, str;

                if ((flag & 1) === 0) {
                    // 短字符串，直接读取结构体中字符串（result+8）
                    strPtr = result.add(8);
                    str = strPtr.readUtf8String();
                    length = str.length;
                } else {
                    // 堆分配的字符串
                    length = result.add(8).readU64();
                    strPtr = result.add(16).readPointer();
                    str = strPtr.readUtf8String();
                }

                console.log(`[sub_B3A8] Result string: "${str}" (len=${length})`);
            } catch (e) {
                console.error('[sub_B3A8] Error:', e);
            }
            console.log('leave sub_B3A8')
        }
    });

}

function hook_system() {
    const libname = libName; // 改成你的

    const waitForLib = () => {
        const m = Process.findModuleByName(libname);
        if (m) {
            console.log("🧬 Found", libname, "at", m.base);
            hook_inline_1();
        } else {
            setTimeout(waitForLib, 100); // 重试
        }
    };

    waitForLib();

}


setImmediate(hook_system);
