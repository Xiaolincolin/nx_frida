const libName = "libgdtqone.so";

function hook_42838(baseAddr) {
    const sub_42838 = baseAddr.add(0x42838);
    Interceptor.attach(sub_42838, {
        onEnter(args) {
            console.log('enter sub_42838')
            let a2 = args[1].readCString();
            let a3 = args[2].readCString();
            console.log(`[sub_42838] a2-> ${a2},a3-> ${a3}`);
            const trace = Thread.backtrace(this.context, Backtracer.ACCURATE)
                .map(addr => DebugSymbol.fromAddress(addr).toString())
                .join("\n");
            console.log("[Call Stack]\n" + trace)
        },

        onLeave(retval) {
            console.log('retval sub_42838')
        }
    });
}

function hook_202AC(baseAddr) {
    const sub_202AC = baseAddr.add(0x202AC);
    Interceptor.attach(sub_202AC, {
        onEnter(args) {
            console.log('enter sub_202AC')
            this.a1 = this.context.x8;
        },

        onLeave(retval) {
            console.log('onLeave sub_202AC')
            console.log('retval sub_202AC', this.a1.add(1).readCString())
        }
    });
}

function hook_49440(baseAddr) {
    const sub_49440 = baseAddr.add(0x49440);
    Interceptor.attach(sub_49440, {
        onEnter(args) {
            this.buf = args[0];
            console.log('enter sub_49440')
        },
        onLeave(retval) {
            const raw = Memory.readByteArray(this.buf, 32);
            console.log("🎲  /dev/urandom data (32 bytes):");
            console.log(hexdump(raw, {offset: 0, length: 32, header: false}));
        }
    });

}

function hook_20518(baseAddr) {
    const sub_20518 = baseAddr.add(0x20518);
    Interceptor.attach(sub_20518, {
        onEnter(args) {
            console.log('enter sub_20518')
        },
        onLeave(retval) {
            console.log('onLeave sub_20518')

        }
    });

}

function hook_17DEC(baseAddr) {
    const sub_17DEC = baseAddr.add(0x17DEC);
    Interceptor.attach(sub_17DEC, {
        onEnter(args) {
            console.log('enter sub_17DEC')
            console.log(hexdump(args[1]));

        },
        onLeave(retval) {
            console.log('leave sub_17DEC')
            var ptr_to_str = Memory.readPointer(retval.add(24)); // result[2]
            console.log('sub_17DEC retval Content =', Memory.readUtf8String(ptr_to_str));
            const trace = Thread.backtrace(this.context, Backtracer.ACCURATE)
                .map(addr => DebugSymbol.fromAddress(addr).toString())
                .join("\n");
            console.log("[Call Stack]\n" + trace)
        }
    });
}

function hook_1BE30(baseAddr) {
    const sub_1BE30 = baseAddr.add(0x1BE30);
    Interceptor.attach(sub_1BE30, {
        onEnter(args) {
            console.log('enter sub_1BE30')

        },
        onLeave(retval) {
            console.log('leave sub_1BE30')
            console.log(hexdump(retval))
        }
    });
}

function hook_main() {
    const baseAddr = Module.findBaseAddress(libName);
    if (!baseAddr) {
        console.error("❌ 未找到模块:", libName);
        return;
    }
    console.log('baseadd', baseAddr)
    // hook_42838(baseAddr);
    // hook_202AC(baseAddr);
    // hook_49440(baseAddr);
    // hook_20518(baseAddr);
    hook_17DEC(baseAddr);
    hook_1BE30(baseAddr);

}

function hook_system() {
    const libname = libName; // 改成你的

    const waitForLib = () => {
        const m = Process.findModuleByName(libname);
        if (m) {
            console.log("🧬 Found", libname, "at", m.base);
            hook_main();
        } else {
            setTimeout(waitForLib, 100); // 重试
        }
    };

    waitForLib();

}


setImmediate(hook_system);
