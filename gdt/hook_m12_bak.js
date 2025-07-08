let libName = "libgdtqone.so"


function hook_inline() {
    const base = Module.findBaseAddress(libName);
    if (!base) {
        console.log('not found base')
        return
    }

    const sub_1C670_addr = base.add(0x1C670);
    console.log(`sub_1C670_addr=${sub_1C670_addr}`)

    Interceptor.attach(sub_1C670_addr, {
        onEnter(args) {
            const a2 = args[2];

            // key 通常在结构开头 inline，直接读字符串（或调试确认）
            try {
                const keyStr = a2.readUtf8String();
                const type = a2.add(0x78).readU32();
                const valPtr = a2.add(0x30).readPointer();

                console.log(`[sub_1C670] Key: ${keyStr}`);
                console.log(`  Type: ${type}`);

                if (type === 1) {
                    const valStr = Memory.readUtf8String(valPtr);
                    console.log(`  Value: ${valStr}`);
                } else {
                    console.log(`  Value Ptr: ${valPtr}`);
                }
            } catch (e) {
                console.log(`[sub_1C670] Decode error: ${e}`);
            }
        }
    });

    const sub_B3A8_addr = base.add(0xB3A8);
    console.log(`sub_B3A8_addr=${sub_B3A8_addr}`)
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
