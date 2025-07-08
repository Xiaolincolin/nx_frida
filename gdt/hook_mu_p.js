function bytesToHex(bytes, opts = {}) {
    const sep = opts.sep !== undefined ? opts.sep : '';
    const upper = opts.upper === true;

    // 兼容 ArrayBuffer
    if (bytes instanceof ArrayBuffer) bytes = new Uint8Array(bytes);

    // Frida Java byte[] 是一个带 .length 的类数组
    if (!bytes || typeof bytes.length !== 'number')
        throw new TypeError('bytesToHex expects an array-like object');

    let out = '';
    for (let i = 0; i < bytes.length; i++) {
        let h = (bytes[i] & 0xff).toString(16).padStart(2, '0');
        if (upper) h = h.toUpperCase();
        out += h;
        if (sep && i !== bytes.length - 1) out += sep;
    }
    return out;
}


function hook_java() {
    let tb = Java.use("com.qq.e.comm.plugin.tb");
    tb["a"].implementation = function (str, str2) {
        console.log(`tb.a is called: str=${str}, str2=${str2}`);
        let result = this["a"](str, str2);
        console.log(`tb.a result=${result}`);
        return result;
    };
}


function hook_classloader() {
    Java.perform(function () {
        Java.enumerateClassLoaders({
            onMatch: function (loader) {
                try {
                    Java.classFactory.loader = loader; // 设置当前 ClassLoader
                    hook_java();

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
    });
}

function hook_a0a0() {
    Java.perform(function () {
        const moduleBase = Module.findBaseAddress("libyaqpro.3e364a2a.so");  // ← 改成你的 so 名字
        const targetAddr = moduleBase.add(0xA0A0);  // sub_A0A0 偏移

        Interceptor.attach(targetAddr, {
            onEnter: function (args) {
                this.env = args[0];
                this.inputArray = args[1];  // jbyteArray 入参
            },
            onLeave: function (retval) {
                if (retval.isNull()) {
                    console.log("❌ sub_A0A0 returned NULL");
                    return;
                }

                console.log("🚀 sub_A0A0 returned jbyteArray:");
                const backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE)
                    .map(addr => DebugSymbol.fromAddress(addr).toString())
                    .join("\n");

                console.log("[Call Stack]\n" + backtrace);
                try {
                    const env = Java.vm.getEnv();
                    const length = env.getArrayLength(retval);
                    const bytes = env.getByteArrayElements(retval, false);
                    const result = Memory.readByteArray(bytes, length);

                    console.log("📦 Result (" + length + " bytes):");
                    console.log(hexdump(result, {
                        offset: 0,
                        length: length,
                        header: true,
                        ansi: true
                    }));

                    // 必须释放 byte array
                    env.releaseByteArrayElements(retval, bytes, 0);
                } catch (e) {
                    console.error("⚠️ Failed to dump jbyteArray:", e);
                }
            }
        });
    });

}

function hook_mu_p() {
    const base = Module.findBaseAddress("libyaqpro.3e364a2a.so");
    if (!base) {
        console.log('not found base')
        return
    }
    hook_classloader();
    const sub_5965C = base.add(0x5965C)
    Interceptor.attach(sub_5965C, {
        onEnter(args) {
            this.arg0 = args[0];
            this.arg3 = args[2];
            console.log('sub_5965C sha1 明文', this.arg0.readCString())
        },

        onLeave(retval) {
            const bytes = Memory.readByteArray(this.arg3, 20);
            console.log("sub_5965C sha1 结果:", bytesToHex(bytes))
        }
    });

    const sub_597E8 = base.add(0x597E8)
    Interceptor.attach(sub_597E8, {
        onEnter(args) {
            let arg1 = args[0].toInt32();
            let arg2 = args[1].toInt32();
            let arg3 = args[2];
            let arg4 = args[3].toInt32();
            this.arg5 = args[4];
            // console.log('enter sub_597E8 明文', `a1=${arg1}`, `a2=${arg2}`, `a3=${arg3.readCString()}`, `a4=${arg4}`)
        },

        onLeave(retval) {
            const bytes = Memory.readByteArray(this.arg5, 32);
            console.log("sub_597E8 转换后的结果:", bytesToHex(bytes))
        }
    });

    // const sub_5505C = base.add(0x5505C)
    // Interceptor.attach(sub_5505C, {
    //     onEnter(args) {
    //         // this.result = args[0];
    //         // let key = args[1];
    //         // const bytes = Memory.readByteArray(key, 32);
    //         // console.log("sub_5505C 进入的key:", bytesToHex(bytes))
    //         this.result_ptr = args[0];  // X0 = result
    //         this.input_ptr = args[1];   // X1 = a2
    //         this.seed = args[7]?.toInt32?.() ?? 0;  // X7 = a8，可能为 undefined
    //     },
    //
    //     onLeave(retval) {
    //         const resultHex = hexdump(this.result_ptr, {
    //             length: 60,
    //             header: false,
    //             ansi: false
    //         });
    //         const inputHex = hexdump(this.input_ptr, {
    //             length: 32,
    //             header: false,
    //             ansi: false
    //         });
    //         console.log("🚀 sub_5505C 调用完成");
    //         console.log("📥 a2 (seed 32B):\n" + inputHex);
    //         console.log("🧂 a8 seed byte:", this.seed);
    //         console.log("📦 result (60B key):\n" + resultHex);
    //     }
    // });

    const sub_5A3E4 = base.add(0x5A3E4)
    Interceptor.attach(sub_5A3E4, {
        onEnter(args) {
            let ptr_data = args[0];
            let size = args[1].toInt32();
            console.log(`📥 sub_5A3E4 明文输入（${size}字节）:`);
            console.log(hexdump(ptr_data, {length: size}));
            console.log('enter sub_5A3E4', args[2].toInt32(), `a4=${args[3].readCString()}`)
            this.outPtrPtr = args[4];   // void **a5
        },
        onLeave(retval) {
            const outBuf = Memory.readPointer(this.outPtrPtr);
            const outLen = retval.toInt32();

            if (outLen > 0 && !outBuf.isNull()) {
                const raw = Memory.readByteArray(outBuf, outLen);
                const hex = Array.from(new Uint8Array(raw))
                    .map(b => b.toString(16).padStart(2, '0'))
                    .join('');
                console.log(`📦 leave sub_5A3E4 输出 (${outLen} bytes):\n${hex}`);
            } else {
                console.log("❌ sub_5A3E4 failed or returned empty buffer");
            }
        }
    });

    // const sub_55374 = base.add(0x55374)
    // Interceptor.attach(sub_55374, {
    //     onEnter(args) {
    //         let sbox = args[0];
    //         this.a5 = args[1];
    //         console.log(`📥 enter sub_55374`);
    //         console.log(`📥 sbox 输入（${hexdump(sbox)}）:`);
    //         console.log(`📥 a5 输入（${hexdump(this.a5, {length: 350})}）:`);
    //
    //     },
    //     onLeave(retval) {
    //
    //     }
    // });
    hook_a0a0()

}

setImmediate(hook_mu_p);
