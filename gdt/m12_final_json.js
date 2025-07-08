let libName = "libgdtqone.so"

function hook_m12_json() {
    const base = Module.findBaseAddress(libName);
    if (!base) {
        console.log('not found base')
        return
    }


    const sub_1AFD0 = base.add(0x1AFD0);
    console.log(`sub_1AFD0=${sub_1AFD0}`)
    Interceptor.attach(sub_1AFD0, {
        onLeave(retval) {
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


}

function hook_system() {
    const libname = libName; // 改成你的

    const waitForLib = () => {
        const m = Process.findModuleByName(libname);
        if (m) {
            console.log("🧬 Found", libname, "at", m.base);
            hook_m12_json();
        } else {
            setTimeout(waitForLib, 100); // 重试
        }
    };

    waitForLib();

}


setImmediate(hook_system);
