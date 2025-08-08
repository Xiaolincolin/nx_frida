function hook_1D05C(baseAddr) {
    const sub_1D05C = baseAddr.add(0x1D05C);
    Interceptor.attach(sub_1D05C, {
        onEnter: function (args) {
            this.a1 = args[0];  // 结构体原始地址
            this.a2 = args[1];  // out_ptr
            this.a3 = args[2];  // out_len
        }, onLeave: function (retval) {
            if (retval.toInt32() !== 0) return;  // 错误跳过

            let output_ptr = Memory.readPointer(this.a2);
            let output_len = Memory.readU32(this.a3);
            console.log("=== sub_1D05C called ===");
            console.log("output ptr:", output_ptr, "len:", output_len);
            let output_bytes = Memory.readByteArray(output_ptr, output_len);
            console.log(hexdump(output_bytes, {length: output_len}));
        }
    });

}

function hook_CD10(baseAddr) {
    const sub_CD10 = baseAddr.add(0xCD10);
    Interceptor.attach(sub_CD10, {
        onEnter: function (args) {
            console.log('enter sub_CD10');
            let a2 = args[1];
            console.log('a2:', a2.readCString());
        },
        onLeave: function (retval) {

        }
    });
}

function hook_27BA8(baseAddr) {
    const sub_27BA8 = baseAddr.add(0x27BA8);
    Interceptor.attach(sub_27BA8, {
        onEnter: function (args) {
            console.log('enter sub_27BA8');
            let a1 = args[0].readPointer();
            console.log('a1:\n', hexdump(a1));
            const backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE)
                .map(addr => DebugSymbol.fromAddress(addr).toString())
                .join("\n");
            console.log("[Call Stack]\n" + backtrace);
        },
        onLeave: function (retval) {

        }
    });
}

function hook_D368(baseAddr) {
    const sub_D368 = baseAddr.add(0xD368);
    Interceptor.attach(sub_D368, {
        onEnter: function (args) {
            this.a1 = args[0].readPointer();
            console.log('sub_D368 enter a1:\n', this.a1.readCString());
        },
        onLeave: function (retval) {
            console.log('enter sub_D368');
            console.log('sub_D368 leave a1:\n', this.a1.readCString());

        }
    });
}

function hook_D148(baseAddr) {
    const sub_D148 = baseAddr.add(0xD148);
    Interceptor.attach(sub_D148, {
        onEnter: function (args) {
            console.log('enter sub_D148');
            this.a1 = args[0].readPointer();
            let a2 = args[1].readCString()
            console.log('sub_D148 a1:\n', this.a1.readCString());
            console.log('sub_D148 a2:\n', a2);
        },
        onLeave: function (retval) {
            console.log('sub_D148 leave a1:\n', this.a1.readCString());

        }
    });
}

function hook_C8D8(baseAddr) {
    const sub_C8D8 = baseAddr.add(0xC8D8);
    Interceptor.attach(sub_C8D8, {
        onEnter: function (args) {
            console.log('enter sub_C8D8');
            // let a1 = args[0].readPointer();
            let a2 = args[1];
            // console.log('sub_C8D8 a1:\n', a1.readCString());
            console.log('sub_C8D8 a2:\n', a2.readCString());
        },
        onLeave: function (retval) {

        }
    });
}

function hook_10C94(baseAddr) {
    const sub_10C94 = baseAddr.add(0x10C94);
    Interceptor.attach(sub_10C94, {
        onEnter: function (args) {
            console.log('enter sub_10C94');
            const sub_4E838 = baseAddr.add(0x4E838);
            console.log('sub_4E838:\n', sub_4E838.add(0x20).readPointer().readCString());
        },
        onLeave: function (retval) {
            let ret = retval.add(0x20).readPointer();
            console.log('sub_10C94 ret:\n', ret.readCString());

        }
    });
}


function hook_1366C(baseAddr) {
    const sub_1366C = baseAddr.add(0x1366C);
    Interceptor.attach(sub_1366C, {
        onEnter: function (args) {
            console.log('enter sub_1366C');
            this.a1 = args[0];
            console.log('sub_1366C enter a1:\n', this.a1.add(0x20).readPointer().readCString());
        },
        onLeave: function (retval) {
            console.log('leave sub_1366C');
            console.log('sub_1366C ret a1:\n', this.a1.add(0x20).readPointer().readCString());
        }
    });
}

function hook_main(libname) {
    const baseAddr = Module.findBaseAddress(libname);
    if (!baseAddr) {
        console.error("❌ 未找到模块:", libname);
        return;
    }
    console.log('baseAddr:', baseAddr);
    hook_1D05C(baseAddr);
    // hook_CD10(baseAddr);
    // hook_27BA8(baseAddr);
    hook_D148(baseAddr);
    hook_D368(baseAddr);
    hook_C8D8(baseAddr);
    hook_10C94(baseAddr);
    // hook_C884(baseAddr);
    hook_1366C(baseAddr);
}

function hook_system() {
    const libname = "libturingau.3e364a2a.so";

    const waitForLib = () => {
        const m = Process.findModuleByName(libname);
        if (m) {
            console.log("🧬 Found", libname, "at", m.base);
            hook_main(libname);
        } else {
            setTimeout(waitForLib, 50); // 重试
        }
    };

    waitForLib();

}


setImmediate(hook_system);

