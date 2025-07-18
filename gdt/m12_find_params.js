const libName = "libgdtqone.so";


function base64Encode(arrayBuffer) {
    const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const bytes = new Uint8Array(arrayBuffer);
    let result = '', i;

    for (i = 0; i < bytes.length; i += 3) {
        let b1 = bytes[i];
        let b2 = i + 1 < bytes.length ? bytes[i + 1] : 0;
        let b3 = i + 2 < bytes.length ? bytes[i + 2] : 0;

        let triplet = (b1 << 16) + (b2 << 8) + b3;

        result += chars[(triplet >> 18) & 0x3F];
        result += chars[(triplet >> 12) & 0x3F];
        result += i + 1 < bytes.length ? chars[(triplet >> 6) & 0x3F] : '=';
        result += i + 2 < bytes.length ? chars[triplet & 0x3F] : '=';
    }

    return result;
}

function toBase64(ptr, len) {
    const buffer = Memory.readByteArray(ptr, len);
    console.log('aes hex:\n');
    console.log(hexdump(buffer, {length: len}))
    console.log('aes base64:\n');
    return base64Encode(buffer);
}

function hook_params_aes(baseAddr) {
    const sub_1F1C8_ptr = baseAddr.add(0x1F1C8);
    Interceptor.attach(sub_1F1C8_ptr, {
        onEnter(args) {
            const keyPtr = args[0]; // a1
            const ivPtr = keyPtr.add(176); // IV
            const plaintextPtr = args[1]; // a2
            const length = args[2].toInt32();

            console.log('[sub_1F1C8] AES Key:');
            console.log(hexdump(keyPtr, {length: 16}));

            console.log('[sub_1F1C8] IV:');
            console.log(hexdump(ivPtr, {length: 16}));

            console.log(`[sub_1F1C8] Plaintext (${length} bytes):`);
            console.log(hexdump(plaintextPtr, {length: length}));

            this.outputPtr = plaintextPtr;
            this.length = length;

        },

        onLeave(retval) {
            console.log('[sub_1F1C8] Encrypted Output (len=' + this.length + '):');
            // console.log(hexdump(this.outPtr, {length: this.len}));
            console.log(toBase64(this.outputPtr, this.length))
        }
    });
}

function hook_body(baseAddr) {
    // 这是最后json生成的地方
    const sub_1AFD0_ptr = baseAddr.add(0x1AFD0);
    Interceptor.attach(sub_1AFD0_ptr, {
        onEnter(args) {

        },
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
                console.log("[sub_1AFD0] string:", str);
            } catch (e) {
                console.warn("[sub_1AFD0] Invalid UTF-8 at offset", e.offset || "?");
            }
        }
    });
}

function hook_aes(baseAddr) {
    const sub_1F0E0_ptr = baseAddr.add(0x1F0E0);
    Interceptor.attach(sub_1F0E0_ptr, {
        onEnter(args) {
            this.a1 = args[0];   // 原始明文结构体
            this.a2 = args[1];   // AES 密钥
            this.a3 = args[2];   // IV 或随机数（可选打印）

            // 读取明文长度
            const flag = this.a1.readU8();
            let len, dataPtr;
            if ((flag & 1) === 0) {
                len = flag >> 1;
                dataPtr = this.a1.add(8);
            } else {
                len = this.a1.add(8).readU32();
                dataPtr = this.a1.add(16).readPointer();
            }
            // 打印密钥（假设 16 字节）
            console.log(`[sub_1F0E0] AES Key:`);
            console.log(hexdump(this.a2.readByteArray(16)));

            // 可选：打印 IV（如果是 CBC 模式）
            console.log(`[sub_1F0E0] IV:`);
            console.log(hexdump(this.a3.readByteArray(16)));

            // 记录明文
            const original = Memory.readByteArray(dataPtr, len);
            console.log(`[sub_1F0E0] enter Plaintext (${len} bytes): \n${hexdump(original, {length: len})}`);
        },

        onLeave(retval) {

        }
    });
}

function hook_17DEC(baseAddr) {
    const sub_17DEC = baseAddr.add(0x17DEC);
    Interceptor.attach(sub_17DEC, {
        onEnter(args) {
            console.log('enter sub_17DEC');
            const keyStr = Memory.readUtf8String(args[1].add(1));
            console.log('[sub_17DEC] Searching key (string):', keyStr);
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

function hook_17F2C(baseAddr) {
    // todo 追踪每个端值的来源的来源，例如k1-k15
    const sub_17F2C = baseAddr.add(0x17F2C);
    Interceptor.attach(sub_17F2C, {
        onEnter(args) {
            this.a1 = args[2];   // 原始明文结构体
            const flag = this.a1.readU8();
            let len, dataPtr;
            if ((flag & 1) === 0) {
                len = flag >> 1;
                dataPtr = this.a1.add(8);
            } else {
                len = this.a1.add(8).readU32();
                dataPtr = this.a1.add(16).readPointer();
            }
            if (len === 0) {
                return
            }
            console.log('hook_17F2C a1->', args[0].readU8())
            const firstByte = Memory.readU8(dataPtr);
            console.log('firstByte:', firstByte)
            const original = Memory.readByteArray(dataPtr, len);
            console.log(`[hook_17F2C] enter (${len} bytes): \n${hexdump(original, {length: len})}`);
            const backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE)
                .map(addr => DebugSymbol.fromAddress(addr).toString())
                .join("\n");
            console.log("[Call Stack]\n" + backtrace);
        },

        onLeave(retval) {

        }
    });
}

function hook_1CCBC(baseAddr) {
    const sub_1CCBC = baseAddr.add(0x1CCBC);
    Interceptor.attach(sub_1CCBC, {
        onEnter(args) {
            console.log('enter sub_1CCBC');
            console.log(hexdump(args[0].add(1)))

        },
        onLeave(retval) {
            console.log('leave sub_1CCBC')
            console.log(hexdump(retval))
        }
    });
}

function hook_28D68(baseAddr) {
    let sub_28D68 = baseAddr.add(0x28D68);
    Interceptor.attach(sub_28D68, {
        onEnter(args) {
            console.log('enter sub_28D68');
            let a1 = args[0];
            let a2 = args[1].toInt32();
            console.log('length:', a2);
            console.log(hexdump(a1, {length: a2}))

        },
        onLeave(retval) {
            console.log('leave sub_28D68')
            console.log(retval.toInt32())
        }
    });

}

function hook_17(baseAddr) {
    let target = baseAddr.add(0x126EC);
    Java.perform(function () {
        console.log("Hooking sub_126EC at", target);
        Interceptor.attach(target, {
            onEnter: function (args) {
                this.env = args[0];
                this.outBuf = args[2];
                this.len = args[3].toInt32();
            },

            onLeave: function (retval) {
                console.log("[*] sub_126EC returned:\n", hexdump(this.outBuf));
            }
        });
    });


}

function hook_java() {
    Java.perform(function () {
        Java.enumerateClassLoaders({
            onMatch: function (loader) {
                try {
                    Java.classFactory.loader = loader; // 设置当前 ClassLoader
                    let U = Java.use("com.android.gdt.qone.uin.U");
                    U["r"].implementation = function (z, i, i2, str, i3, strArr, str2) {
                        console.log(`U.r is called: z=${z}, i=${i}, i2=${i2}, str=${str}, i3=${i3}, strArr=${strArr}, str2=${str2}`);
                        let result = this["r"](z, i, i2, str, i3, strArr, str2);
                        console.log(`U.r result=${result}`);
                        return result;
                    };

                } catch (error) {
                    if (error.message.includes("ClassNotFoundException")) {
                        // 忽略 ClassNotFound 异常，继续尝试下一个 ClassLoader
                    } else {
                        console.error(`[Error] Loader ${loader}: ${error}`);
                    }
                }
            },
            onComplete: function () {
                console.log("[Info] ClassLoader enumeration complete.");
            }
        });

    })
}

function hook_main() {
    const baseAddr = Module.findBaseAddress(libName);
    if (!baseAddr) {
        console.error("❌ 未找到模块:", libName);
        return;
    }
    console.log('baseadd', baseAddr);
    hook_aes(baseAddr);
    hook_body(baseAddr);
    hook_params_aes(baseAddr);
    hook_17F2C(baseAddr);
    hook_1CCBC(baseAddr);
    hook_17DEC(baseAddr);
    hook_17(baseAddr);
    hook_28D68(baseAddr);
    hook_java();
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
