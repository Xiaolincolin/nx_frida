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
    return base64Encode(buffer);
}

function hook_params() {

    const baseAddr = Module.findBaseAddress(libName);
    if (!baseAddr) {
        console.error("❌ 未找到模块:", libName);
        return;
    }

    const sub_1D6F0 = baseAddr.add(0x1D6F0);
    Interceptor.attach(sub_1D6F0, {
        onEnter(args) {
            console.log("[+] sub_1D6F0 enter");

        },
        onLeave(retval) {
            console.log("[+] sub_1D6F0 time returned:");
            let time_hex = retval.toString();
            console.log(time_hex);
            console.log('time:', parseInt(time_hex, 16)); // ✅ 结果: 1715004)
        }
    });

    const sub_22A7C = baseAddr.add(0x22A7C);
    Interceptor.attach(sub_22A7C, {
        onEnter(args) {
            this.a1 = args[0];
            this.a2 = args[1].toInt32();

            // 限制最大长度避免崩溃
            if (this.a2 > 0) {
                try {
                    const data = Memory.readByteArray(this.a1, this.a2);
                    console.log(`[+] sub_22A7C called`);
                    console.log(`    a1 (ptr): ${this.a1}`);
                    console.log(`    a2 (len): ${this.a2}`);
                    console.log(hexdump(data, {
                        length: this.a2,
                    }));
                } catch (e) {
                    console.error(`[!] Failed to read a1: ${e}`);
                }
            }
        }
        ,
        onLeave(retval) {
            const v13 = retval;
            const size = 26; // 最少
            console.log('[+] sub_22A7C leave =', v13);
            console.log(hexdump(v13, {length: size}));
        }
    });


    const sub_20720 = baseAddr.add(0x20720);
    Interceptor.attach(sub_20720, {
        onEnter(args) {
            this.a1 = args[0];  // v20
            this.a2 = args[1];  // v17
            this.a3 = args[2];  // output to v16 (a3)

            // 解析 a1
            const tag1 = this.a1.readU64();
            let len1 = 0, ptr1;
            if (tag1 & 1) {
                len1 = this.a1.add(8).readU64();
                ptr1 = this.a1.add(16).readPointer();
            } else {
                len1 = tag1 >> 1;
                ptr1 = this.a1.add(8);
            }

            console.log('[+] a1 (v20): len =', len1);
            console.log(hexdump(ptr1, {length: len1}));

            // 解析 a2
            const tag2 = this.a2.readU64();
            let len2 = 0, ptr2;
            if (tag2 & 1) {
                len2 = this.a2.add(8).readU64();
                ptr2 = this.a2.add(16).readPointer();
            } else {
                len2 = tag2 >> 1;
                ptr2 = this.a2.add(8);
            }

            console.log('[+] a2 (v17): len =', len2);
            console.log(hexdump(ptr2, {length: len2}));
        },

        onLeave(retval) {
            // 输出结构 (a3 = v16)
            const tag = this.a3.readU64();
            let length = 0, ptr;
            if (tag & 1) {
                length = this.a3.add(8).readU64();
                ptr = this.a3.add(16).readPointer();
            } else {
                length = tag >> 1;
                ptr = this.a3.add(8);
            }

            console.log('[+] sub_20720 result: len =', length);
            console.log(hexdump(ptr, {length}));
        }
    });


    const sub_A770 = baseAddr.add(0xA770);
    Interceptor.attach(sub_A770, {
        onEnter(args) {
            console.log(`[+] sub_A770 进入`)
            console.log(args[0].readCString())

        },
        onLeave(retval) {
            console.log(`[+] sub_A770 离开`)
            console.log(retval.readCString())
        }
    });

    const sub_2318C = baseAddr.add(0x2318C);
    Interceptor.attach(sub_2318C, {
        onEnter(args) {

        },
        onLeave(retval) {
            console.log(`[+] sub_2318C 离开`)
            console.log(retval.readCString())
        }
    });

    const sub_25588 = baseAddr.add(0x25588);
    Interceptor.attach(sub_25588, {
        onEnter(args) {

        },
        onLeave(retval) {
            console.log(`[+] sub_25588 离开入`)
            console.log(retval.readCString())
        }
    });

    const sub_17F2C = baseAddr.add(0x17F2C);
    Interceptor.attach(sub_17F2C, {
        onEnter(args) {
            this.a2 = args[2];
            // console.log(`[+] sub_17F2C 进入`)
            // 读取明文长度
            const flag = this.a2.readU8();
            let len, dataPtr;
            if ((flag & 1) === 0) {
                len = flag >> 1;
                dataPtr = this.a2.add(8);
            } else {
                len = this.a2.add(8).readU32();
                dataPtr = this.a2.add(16).readPointer();
            }
            let str_d = dataPtr.readCString()
            if (str_d.endsWith("0000000000000000")) {
                console.log(`[sub_17F2C] (${len} bytes)\n${str_d}`)
                const backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE)
                    .map(addr => DebugSymbol.fromAddress(addr).toString())
                    .join("\n");
                console.log("[Call Stack]\n" + backtrace);
            }

        }
    });

    const sub_1812C = baseAddr.add(0x1812C);
    Interceptor.attach(sub_1812C, {
        onEnter(args) {
            this.a2 = args[1];
            // console.log(`[+] sub_1812C 进入`)
            // 读取明文长度
            const flag = this.a2.readU8();
            let len, dataPtr;
            if ((flag & 1) === 0) {
                len = flag >> 1;
                dataPtr = this.a2.add(8);
            } else {
                len = this.a2.add(8).readU32();
                dataPtr = this.a2.add(16).readPointer();
            }
            let str_d = dataPtr.readCString()
            if (str_d.endsWith("0000000000000000")) {
                console.log(`[sub_1812C] (${len} bytes)\n${str_d}`)
                const backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE)
                    .map(addr => DebugSymbol.fromAddress(addr).toString())
                    .join("\n");
                console.log("[Call Stack]\n" + backtrace);
            }

        }
    });

    // const sub_1F1C8_ptr = baseAddr.add(0x1F1C8);
    // Interceptor.attach(sub_1F1C8_ptr, {
    //     onEnter(args) {
    //         const keyPtr = args[0]; // a1
    //         const ivPtr = keyPtr.add(176); // IV
    //         const plaintextPtr = args[1]; // a2
    //         const length = args[2].toInt32();
    //
    //         console.log('[sub_1F1C8] AES Key:');
    //         console.log(hexdump(keyPtr, {length: 16}));
    //
    //         console.log('[sub_1F1C8] IV:');
    //         console.log(hexdump(ivPtr, {length: 16}));
    //
    //         console.log(`[sub_1F1C8] Plaintext (${length} bytes):`);
    //         console.log(hexdump(plaintextPtr, {length: length}));
    //
    //         this.outputPtr = plaintextPtr;
    //         this.length = length;
    //
    //     },
    //
    //     onLeave(retval) {
    //         console.log('[sub_1F1C8] Encrypted Output (len=' + this.length + '):');
    //         // console.log(hexdump(this.outPtr, {length: this.len}));
    //         console.log(toBase64(this.outputPtr, this.length))
    //     }
    // });
    //
    //
    // const sub_1AFD0_ptr = baseAddr.add(0x1AFD0);
    // Interceptor.attach(sub_1AFD0_ptr, {
    //     onEnter(args) {
    //
    //     }, onLeave(retval) {
    //         const out = this.context.x0;  // 或 args[1]
    //         const tag = Memory.readU64(out);
    //         let ptr, len;
    //         if ((tag & 1) === 0) {
    //             len = tag >>> 1;
    //             ptr = out.add(8);
    //         } else {
    //             len = Memory.readU64(out.add(8));
    //             ptr = Memory.readPointer(out.add(16));
    //         }
    //         try {
    //             const str = Memory.readUtf8String(ptr);  // 不给 len，Frida 自动遇 0 终止
    //             console.log("[sub_1AFD0] string:", str);
    //         } catch (e) {
    //             console.warn("[sub_1AFD0] Invalid UTF-8 at offset", e.offset || "?");
    //         }
    //     }
    // });
}

function hook_system() {
    const libname = libName; // 改成你的

    const waitForLib = () => {
        const m = Process.findModuleByName(libname);
        if (m) {
            console.log("🧬 Found", libname, "at", m.base);
            hook_params();
        } else {
            setTimeout(waitForLib, 100); // 重试
        }
    };

    waitForLib();

}


setImmediate(hook_system);