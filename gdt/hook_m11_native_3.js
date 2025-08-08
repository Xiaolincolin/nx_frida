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


function hook_1C418(baseAddr) {
    const sub_1C418 = baseAddr.add(0x1C418);
    Interceptor.attach(sub_1C418, {
        onEnter: function (args) {
            console.log('enter sub_1C418');
            let a2 = args[1].toInt32();
            let a3 = args[2];
            console.log('a2:', a2)
            console.log('a3:\n', a3.readCString())
        },
        onLeave: function (retval) {
            console.log('leave sub_1C418');
        }
    });
}

function hook_EFAC(baseAddr) {
    const sub_EFAC = baseAddr.add(0xEFAC);
    Interceptor.attach(sub_EFAC, {
        onEnter: function (args) {
            console.log('enter sub_EFAC');
            let a1 = args[0];
            let a2 = args[1].toInt32();
            let a3 = args[2];
            console.log('a1:\n', hexdump(a1, {length: a2}))
            console.log('a3:\n', a3)
        },
        onLeave: function (retval) {
            console.log('leave sub_EFAC');
            console.log('retval:', retval)
        }
    });
}

function hook_CAF0(baseAddr) {
    const sub_CAF0 = baseAddr.add(0xCAF0);
    Interceptor.attach(sub_CAF0, {
        onEnter: function (args) {
            console.log('enter sub_CAF0');
            this.a1 = args[0];
            console.log('enter a1:\n', this.a1.readPointer().readCString())
            console.log('enter a3:\n', args[2].readPointer().toUInt32().toString(16))
        },
        onLeave: function (retval) {
            console.log('leave sub_CAF0');
            console.log('leave a1:\n', this.a1.readPointer().readCString())
        }
    });
}

function hook_CEF0(baseAddr) {
    const sub_CEF0 = baseAddr.add(0xCEF0);
    Interceptor.attach(sub_CEF0, {
        onEnter(args) {
            let format = args[1].readCString();
            console.log("format:", format);

            if (format === "%x") {
                let value = args[2].toUInt32();  // 读取传入的 uint32 值
                console.log("arg (calculated value) = 0x" + value.toString(16));
            }
        }
    });
}

function hook_39C28(baseAddr) {
    const sub_39C28 = baseAddr.add(0x39C28);
    Interceptor.attach(sub_39C28, {
        onEnter(args) {
            console.log('enter sub_39C28');
            console.log('a3:\n', args[3])
        }
    });
}

function hook_1C218(baseAddr) {
    const sub_1C218 = baseAddr.add(0x1C218);
    Interceptor.attach(sub_1C218, {
        onEnter(args) {
            console.log('enter sub_1C218');
            console.log('a1:\n', args[1].readCString())
        },
        onLeave(retval) {
            console.log('leave sub_1C218');
            console.log('retval:', retval.readCString())
        }
    });
}

function hook_F1D4(baseAddr) {
    const sub_F1D4 = baseAddr.add(0xF1D4);
    Interceptor.attach(sub_F1D4, {
        onEnter(args) {
            console.log('enter sub_F1D4');
            let a1 = args[0].add(0x10).readPointer();
            console.log('a1:\n', hexdump(a1))

            let list_head = args[0].readPointer();     // *a1
            let node = list_head.add(16).readPointer(); // *(list + 16)
            while (!node.equals(list_head)) {
                let val = node.readU64();  // ← 这就是 vld1q_dup_f64(v3) 读取的值
                console.log("Node value:", val.toString(16));
                node = node.add(16).readPointer(); // next
            }
        },
        onLeave(retval) {
            console.log('leave sub_F1D4');
        }
    });
}

function hook_F4D8(baseAddr) {
    const sub_F4D8 = baseAddr.add(0xF4D8);
    Interceptor.attach(sub_F4D8, {
        onEnter(args) {
            console.log('enter sub_F4D8');
            let a1 = args[0].readCString();
            console.log('a1:\n', a1)
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
    hook_1C418(baseAddr);
    // hook_EFAC(baseAddr); // 签名的组成方式，暂时屏蔽
    // hook_CAF0(baseAddr); // 签名生成的循环过程，太长了，暂时屏蔽
    hook_CEF0(baseAddr);
    hook_39C28(baseAddr);
    hook_1C218(baseAddr);
    hook_F1D4(baseAddr);
    hook_F4D8(baseAddr);
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

