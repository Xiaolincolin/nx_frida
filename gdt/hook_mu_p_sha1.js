function getSymbol(name) {
    let symbols = Process.getModuleByName("libart.so").enumerateSymbols();
    let addr_target = null;
    for (let index = 0; index < symbols.length; index++) {
        const symbols_one = symbols[index];
        if (symbols_one.name.indexOf("art") >= 0) {
            if (
                symbols_one.name.indexOf("CheckJNI") === -1 &&
                symbols_one.name.indexOf("Notify") === -1 &&
                symbols_one.name.indexOf("mirror") === -1 &&
                symbols_one.name.indexOf("verifier") === -1 &&
                symbols_one.name.indexOf("DexFile") === -1 &&
                symbols_one.name.indexOf("JNIILb1") === -1
            ) {
                if (
                    symbols_one.name.indexOf(name) >= 0
                ) {
                    console.log("target  symbols", JSON.stringify(symbols_one));
                    addr_target = symbols_one.address;
                    console.log("target address = " + addr_target);
                    return addr_target
                }

                // break
            }
        }
    }
}

function toHex(bytes) {
    return Array.from(bytes, b => b.toString(16).padStart(2, "0")).join("");
}

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
    Java.perform(() => {
        let xx = Java.use("com.qq.e.comm.plugin.xx");
        xx["b"].overload('[B').implementation = function (bArr) {
            // console.log(`xx.b is called: bArr=${bArr}`);
            let result = this["b"](bArr);
            // console.log(`xx.b result=${result}`);
            const hex = bytesToHex(result);
            console.log(`📦 xx.b 返回 byte[${result.length}]:\n${hex}`);

            return result;
        };
    });


}

function hook_mu_p_sha1() {
    const base = Module.findBaseAddress("libyaqpro.3e364a2a.so");
    if (!base) {
        console.log('not found base')
        return
    }
    let jni_address = getSymbol('GetByteArrayElements')
    if (!jni_address) {
        console.log('not found jni_address')
    }
    const sha1Addr = base.add(0x56214);
    console.log("[*] sha1_transform @", sha1Addr);
    // Interceptor.attach(sha1Addr, {
    //     onEnter(args) {
    //         // 保存上下文指针，留给 onLeave 用
    //         this.ctx = args[0];               // SHA1_CTX*
    //         this.block = args[1];               // 数据块指针
    //
    //         /* ---------- 打印输入块 ---------- */
    //         const buf = Memory.readCString(this.block);
    //         console.log('enter sub_56214 transform明文:', buf)
    //
    //     },
    //
    //     onLeave(retval) {
    //         /* ---------- 打印 state[5] (after) ---------- */
    //         const stateAfter = [];
    //         for (let i = 0; i < 5; i++) {
    //             stateAfter.push(
    //                 Memory.readU32(this.ctx.add(i * 4))
    //                     .toString(16).padStart(8, "0")
    //             );
    //         }
    //         console.log("📤📤📤 leave sub_56214 transform result:", stateAfter.join(" "));
    //     }
    // });
    //
    // const sha1Update = base.add(0x5917C)
    // Interceptor.attach(sha1Update, {
    //     onEnter(args) {
    //         this.arg1 = args[1]
    //         console.log('enter sub_5917C update 明文', this.arg1.add(0x1c).readCString())
    //
    //     },
    //     onLeave(retval) {
    //         const stateAfter = [];
    //         for (let i = 0; i < 5; i++) {
    //             stateAfter.push(
    //                 Memory.readU32(this.arg1.add(i * 4))
    //                     .toString(16).padStart(8, "0")
    //             );
    //         }
    //         console.log(' 📤 leave sub_5917C update', stateAfter.join(""))
    //
    //     }
    //
    // })

    const sub_5965C = base.add(0x5965C)
    Interceptor.attach(sub_5965C, {
        onEnter(args) {
            this.arg0 = args[0];
            this.arg3 = args[2];
            console.log('enter sub_5965C 明文', this.arg0.readCString())
        },

        onLeave(retval) {
            const bytes = Memory.readByteArray(this.arg3, 20);
            const hexStr = Array.from(new Uint8Array(bytes))
                .map(b => b.toString(16).padStart(2, '0'))
                .join('');
            console.log("leave sub_5965C 🔢 参数 hex:", hexStr);

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
            console.log('enter sub_597E8 明文', `a1=${arg1}`, `a2=${arg2}`, `a3=${arg3.readCString()}`, `a4=${arg4}`)
        },

        onLeave(retval) {
            const buf = Memory.readByteArray(this.arg5, 32);  // ptr 是返回数据地址，40 是你已知的长度
            const hexStr = toHex(new Uint8Array(buf));
            console.log("leave sub_597E8 ", hexStr);
        }
    });

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
                const raw = Memory.readByteArray(outBuf, outLen + 16);
                const hex = Array.from(new Uint8Array(raw))
                    .map(b => b.toString(16).padStart(2, '0'))
                    .join('');
                console.log(`📦 leave sub_5A3E4 输出 (${outLen} bytes):\n${hex}`);
            } else {
                console.log("❌ sub_5A3E4 failed or returned empty buffer");
            }
        }
    });


    // const sub_A0A0 = base.add(0xA0A0)
    // Interceptor.attach(sub_A0A0, {
    //     onEnter(args) {
    //         const backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE)
    //             .map(addr => DebugSymbol.fromAddress(addr).toString())
    //             .join("\n");
    //         console.log("sub_A0A0 [Call Stack]\n" + backtrace);
    //         const env = args[0];
    //         const jbyteArrayObj = args[1];
    //
    //         // 调用 JNI GetByteArrayElements
    //         const jni = new NativeFunction(
    //             jni_address,
    //             'pointer', ['pointer', 'pointer', 'pointer']
    //         );
    //         const realBytesPtr = jni(env, jbyteArrayObj, ptr(0));
    //         console.log("🔍 GetByteArrayElements ->", realBytesPtr);
    //         console.log('sub_A0A0 明文解耦', hexdump(realBytesPtr, {length: 64}));
    //     },
    //     onLeave() {
    //     }
    // });
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


setImmediate(hook_mu_p_sha1);

