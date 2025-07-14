const libName = "libgdtqone.so";

function hook_1F0E0(baseAddr) {
    const sub_1F0E0_ptr = baseAddr.add(0x1F0E0);
    Interceptor.attach(sub_1F0E0_ptr, {
        onEnter(args) {
            this.a1 = args[0];   // 原始明文结构体
            const flag = this.a1.readU8();
            let len, dataPtr;
            if ((flag & 1) === 0) {
                len = flag >> 1;
                dataPtr = this.a1.add(8);
            } else {
                len = this.a1.add(8).readU32();
                dataPtr = this.a1.add(16).readPointer();
            }
            const original = Memory.readByteArray(dataPtr, len);
            console.log(`[sub_1F0E0] enter Plaintext (${len} bytes): \n${hexdump(original, {length: len})}`);
            // const backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE)
            //     .map(addr => DebugSymbol.fromAddress(addr).toString())
            //     .join("\n");
            //
            // console.log("[Call Stack]\n" + backtrace);
        },

        onLeave(retval) {

        }
    });
}

function hook_43BDC(baseAddr) {
    const target = baseAddr.add(0x43BDC);
    Interceptor.attach(target, {
        onEnter(args) {
            this.a1 = this.context.x5.add(0x18);
            console.log('enter hook_43BDC')
            console.log('a4:', args[3].toInt32())
            const flag = this.a1.readU8();
            let len, dataPtr;
            if ((flag & 1) === 0) {
                len = flag >> 1;
                dataPtr = this.a1.add(8);
            } else {
                len = this.a1.add(8).readU32();
                dataPtr = this.a1.add(16).readPointer();
            }
            const original = Memory.readByteArray(dataPtr, len);
            console.log(`[hook_43BDC]01 enter Plaintext (${len} bytes): \n${hexdump(original, {length: len})}`);

            const backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE)
                .map(addr => DebugSymbol.fromAddress(addr).toString())
                .join("\n");
            console.log("[Call Stack]\n" + backtrace);
        },

        onLeave(retval) {
        }
    });
}


function hook_10444(baseAddr) {
    const sub_10444 = baseAddr.add(0x10444);
    Interceptor.attach(sub_10444, {
        onEnter(args) {
            console.log('enter sub_10444')
            this.a1 = args[3];
            const flag = this.a1.readU8();
            let len, dataPtr;
            if ((flag & 1) === 0) {
                len = flag >> 1;
                dataPtr = this.a1.add(8);
            } else {
                len = this.a1.add(8).readU32();
                dataPtr = this.a1.add(16).readPointer();
            }
            const original = Memory.readByteArray(dataPtr, len);
            console.log(`[hook_B3A8]02 enter Plaintext (${len} bytes): \n${hexdump(original, {length: len})}`);
            const backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE)
                .map(addr => DebugSymbol.fromAddress(addr).toString())
                .join("\n");
            console.log("[Call Stack a]\n" + backtrace);
        },

        onLeave(retval) {

        }
    });
}

function hook_23E98(baseAddr) {
    const sub_23E98 = baseAddr.add(0x23E98);
    Interceptor.attach(sub_23E98, {
        onEnter(args) {
            console.log('enter sub_23E98')
            this.a1 = this.context.x8;
            const flag = this.a1.readU8();
            let len, dataPtr;
            if ((flag & 1) === 0) {
                len = flag >> 1;
                dataPtr = this.a1.add(8);
            } else {
                len = this.a1.add(8).readU32();
                dataPtr = this.a1.add(16).readPointer();
            }
            const original = Memory.readByteArray(dataPtr, len);
            console.log(`[sub_23E98] enter Plaintext (${len} bytes): \n${hexdump(original, {length: len})}`);
        },

        onLeave(retval) {
            const flag = this.a1.readU8();
            let len, dataPtr;
            if ((flag & 1) === 0) {
                len = flag >> 1;
                dataPtr = this.a1.add(8);
            } else {
                len = this.a1.add(8).readU32();
                dataPtr = this.a1.add(16).readPointer();
            }
            const original = Memory.readByteArray(dataPtr, len);
            console.log(`[sub_23E98] retval Plaintext (${len} bytes): \n${hexdump(original, {length: len})}`);
        }
    });
}

function hook_23FA0(baseAddr) {
    const sub_23FA0 = baseAddr.add(0x23FA0);
    Interceptor.attach(sub_23FA0, {
        onEnter(args) {
            this.a1 = args[0];
            const a2 = args[1];
            const tag = Memory.readU8(a2);

            let data_ptr, data_len;

            if (tag & 1) {
                // heap 模式
                data_len = Memory.readU64(a2.add(8));
                data_ptr = Memory.readPointer(a2.add(16));
                console.log('[HEAP] len =', data_len, ' ptr =', data_ptr);
            } else {
                // inline 模式
                data_len = tag >> 1;
                data_ptr = a2.add(1);
                console.log('[INLINE] len =', data_len);
            }

            if (data_len > 0 && data_len < 0x1000) {
                console.log(hexdump(data_ptr, {length: data_len}));
            } else {
                console.log('[!] Abnormal length:', data_len);
            }
        },
        onLeave(retval) {
            console.log('leave sub_23FA0')
            try {
                const a1 = this.a1;
                const tag = Memory.readU64(a1);

                let data_ptr, data_len;

                if (tag & 1) {
                    // heap 模式
                    data_len = Memory.readU64(a1.add(8));
                    data_ptr = Memory.readPointer(a1.add(16));
                    console.log('[sub_23FA0] [HEAP RESULT] len =', data_len, ' ptr =', data_ptr);
                } else {
                    // inline 模式
                    data_len = tag >> 1;
                    data_ptr = a1.add(8);
                    console.log('[sub_23FA0] [INLINE RESULT] len =', data_len);
                }

                // 打印结果数据
                if (data_len > 0 && data_len < 0x1000) {
                    console.log('[sub_23FA0] Result Data:');
                    console.log(hexdump(data_ptr, {length: data_len}));
                }
            } catch (e) {
                console.error('Failed to decode a1 result:', e);
            }
        }
    });

}

function hook_23878(baseAddr) {
    const sub_23878 = baseAddr.add(0x23878);

    Interceptor.attach(sub_23878, {
        onEnter(args) {
            console.log('enter sub_23878')
            this.a1 = args[1];
            const flag = this.a1.readU8();
            let len, dataPtr;
            if ((flag & 1) === 0) {
                len = flag >> 1;
                dataPtr = this.a1.add(8);
            } else {
                len = this.a1.add(8).readU32();
                dataPtr = this.a1.add(16).readPointer();
            }
            const original = Memory.readByteArray(dataPtr, len);
            console.log(`[sub_23878] enter Plaintext (${len} bytes): \n${hexdump(original, {length: len})}`);
        },
        onLeave(retval) {
            console.log('retval sub_23878')
            const flag = this.a1.readU8();
            let len, dataPtr;
            if ((flag & 1) === 0) {
                len = flag >> 1;
                dataPtr = this.a1.add(8);
            } else {
                len = this.a1.add(8).readU32();
                dataPtr = this.a1.add(16).readPointer();
            }
            const original = Memory.readByteArray(dataPtr, len);
            console.log(`[sub_23878] retval Plaintext (${len} bytes): \n${hexdump(original, {length: len})}`);

        }
    });
}

function hook_23A50(baseAddr) {
    const sub_23A50 = baseAddr.add(0x23BC4);

    Interceptor.attach(sub_23A50, {
        onEnter(args) {
            console.log('enter sub_23A50')
            this.a1 = args[0];
            const flag = this.a1.readU8();
            let len, dataPtr;
            if ((flag & 1) === 0) {
                len = flag >> 1;
                dataPtr = this.a1.add(8);
            } else {
                len = this.a1.add(8).readU32();
                dataPtr = this.a1.add(16).readPointer();
            }
            const original = Memory.readByteArray(dataPtr, len);
            console.log(`[sub_23A50] enter Plaintext (${len} bytes): \n${hexdump(original, {length: len})}`);
        },
        onLeave(retval) {
            console.log('retval sub_23A50')
        }
    });
}

function hook_main() {
    const baseAddr = Module.findBaseAddress(libName);
    if (!baseAddr) {
        console.error("❌ 未找到模块:", libName);
        return;
    }
    console.log('baseadd', baseAddr);
    // hook_tmp(baseAddr);
    // hook_10444(baseAddr);
    // hook_23E98(baseAddr);
    hook_23FA0(baseAddr);
    hook_23878(baseAddr);
    // hook_23A50(baseAddr);
    // hook_43BDC(baseAddr);
    // hook_1F0E0(baseAddr);
    // hook_1812C(baseAddr);
    // hook_17F2C(baseAddr);
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
