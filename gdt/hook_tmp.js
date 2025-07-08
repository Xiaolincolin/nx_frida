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

function parse_key(retval) {
    let key_offset = [0x8, 0x20, 0x38, 0x50, 0x68, 0x80];
    let key_name = ['key', 'params', 'time', 'nonce', 'sign', 'extra'];
    for (let i = 0; i < key_offset.length; i++) {
        let sign_addr = retval.add(key_offset[i]);
        const isHeap = sign_addr.readU64() & 1;
        let dataPtr;
        let len;
        let key_value = key_name[i];
        console.log(`[${key_value} -> value]`);

        try {
            if (isHeap) { // 不等于0，是堆内存
                len = sign_addr.add(8).readU64();
                dataPtr = sign_addr.add(16).readPointer();
            } else {
                len = (sign_addr.readU64() >> 1);
                dataPtr = sign_addr.add(8);
            }
            console.log(hexdump(dataPtr, {length: len}));
        } catch (e) {
            console.error("❌ 解析失败:", e.message || "");
        }
    }
}


function hook_tmp() {
    const baseAddr = Module.findBaseAddress(libName);
    if (!baseAddr) {
        console.error("❌ 未找到模块:", libName);
        return;
    }
    // const target = baseAddr.add(0x25B0C);  // 替换为你的 sub_A900 地址
    // Interceptor.attach(target, {
    //     onEnter(args) {
    //         // const backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE)
    //         //     .map(addr => DebugSymbol.fromAddress(addr).toString())
    //         //     .join("\n");
    //         //
    //         // console.log("[Call Stack]\n" + backtrace);
    //         // this.a1 = args[2];   // 原始明文结构体
    //         // const isHeap = this.a1.readU64() & 1;
    //         // let dataPtr;
    //         // let len;
    //         // if (isHeap) { // 不等于0，是堆内存
    //         //     len = this.a1.add(8).readU64();
    //         //     dataPtr = this.a1.add(16).readPointer();
    //         // } else {
    //         //     len = (this.a1.readU64() >> 1);
    //         //     dataPtr = this.a1.add(8);
    //         // }
    //         // console.log(`[target iv] enter Plaintext =`);
    //         // console.log(hexdump(dataPtr, {length: len}));
    //     },
    //     onLeave: function (retval) {
    //         parse_key(retval)
    //     }
    // });


    const sub_104D0 = baseAddr.add(0x104D0);
    const sub_111E0 = baseAddr.add(0x111E0);
    const sub_11E04 = baseAddr.add(0x11E04);


    // Hook sub_111E0：获取 RSA 公钥字符串
    Interceptor.attach(sub_111E0, {
        onEnter(args) {
            this.arg0 = args[0].toInt32();
            this.arg1 = args[1].toInt32();
        },
        onLeave(retval) {
            const keyStr = Memory.readCString(retval);
            console.log(`[+] sub_111E0(${this.arg0}, ${this.arg1}) 返回公钥字符串: ${keyStr}`);
        }
    });

    // Interceptor.attach(sub_104D0, {
    //     onEnter(args) {
    //         console.log("sub_104D0 onEnter");
    //         const data = args[1];
    //         const len = args[2].toInt32();
    //         this.out = args[3];
    //         console.log('[+] sub_104D0 输入', hexdump(data, {length: len}));
    //     },
    //     onLeave(retval) {
    //         console.log("sub_104D0 onLeave");
    //         // let ptr = Memory.readPointer(this.out.add(16));
    //         // console.log(hexdump(ptr));
    //     }
    // });
    //
    // Interceptor.attach(sub_11E04, {
    //     onEnter(args) {
    //         this.jni_func = args[2].readCString();
    //
    //     },
    //     onLeave(retval) {
    //     }
    // });


    // const sub_1F0E0_ptr = baseAddr.add(0x1F0E0);  // 替换为你的 sub_A900 地址
    // Interceptor.attach(sub_1F0E0_ptr, {
    //     onEnter(args) {
    //         this.a1 = args[0];   // 原始明文结构体
    //         this.a2 = args[1];   // AES 密钥
    //         this.a3 = args[2];   // IV 或随机数（可选打印）
    //         this.a4 = args[3];   // 输出结构体
    //
    //         // 打印密钥（假设 16 字节）
    //         console.log(`[sub_1F0E0] AES Key:`);
    //         console.log(hexdump(this.a2.readByteArray(16)));
    //
    //         // 可选：打印 IV（如果是 CBC 模式）
    //         console.log(`[sub_1F0E0] IV:`);
    //         console.log(hexdump(this.a3.readByteArray(16)));
    //
    //         // 打印原始明文结构体
    //         const isHeap = this.a1.readU64() & 1;
    //         let dataPtr;
    //         let len;
    //         if (isHeap) { // 不等于0，是堆内存
    //             len = this.a1.add(8).readU64();
    //             dataPtr = this.a1.add(16).readPointer();
    //         } else {
    //             len = (this.a1.readU64() >> 1);
    //             dataPtr = this.a1.add(8);
    //         }
    //         console.log(`[sub_1F0E0] Plaintext =`);
    //         console.log(hexdump(dataPtr, {length: len}));
    //     },
    //     onLeave: function (retval) {
    //
    //     }
    //
    // });
    //
    //
    // const sub_1F1C8_ptr = baseAddr.add(0x1F1C8);  // 替换为你的 sub_A900 地址
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
    //         console.log('[sub_1F1C8] Plaintext (before encrypt):');
    //         console.log(hexdump(plaintextPtr, {length}));
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
    //             console.log("Partial string:", str);
    //         } catch (e) {
    //             console.warn("Invalid UTF-8 at offset", e.offset || "?");
    //         }
    //     }
    // });


    // const sub_1F45C_ptr = baseAddr.add(0x1F45C);  // 替换为你的 sub_A900 地址
    // Interceptor.attach(sub_1F45C_ptr, {
    //     onEnter(args) {
    //         console.log(`[sub_1F45C_ptr] enter`);
    //     },
    //     onLeave(retval) {
    //         console.log(`[sub_1F45C_ptr] leave`);
    //
    //     }
    // });
    //
    //
    // const sub_1F528_ptr = baseAddr.add(0x1F528);  // 替换为你的 sub_A900 地址
    // Interceptor.attach(sub_1F528_ptr, {
    //     onEnter(args) {
    //         console.log(`[sub_1F528_ptr] enter`);
    //     },
    //     onLeave(retval) {
    //         console.log(`[sub_1F528_ptr] leave`);
    //
    //     }
    // });

    // let hook = false;
    // const sub_BBC4_ptr = baseAddr.add(0xBBC4);  // 替换为你的 sub_A900 地址
    // Interceptor.attach(sub_BBC4_ptr, {
    //     onEnter(args) {
    //         if (hook) {
    //             this.result = args[0];
    //             this.len = args[1].toInt32();
    //             console.log(`[sub_BBC4] target len = ${this.len}`);
    //         }
    //
    //     },
    //     onLeave(retval) {
    //         if (hook) {
    //             const tag = this.result.readU64();
    //             const isHeap = tag & 1;
    //             const size = isHeap ? this.result.add(8).readU64() : (tag >> 1);
    //             const dataPtr = isHeap ? this.result.add(16).readPointer() : this.result.add(8);
    //             console.log(`[sub_BBC4] result size=${size}, data=${hexdump(dataPtr, {length: size})}`);
    //         }
    //
    //     }
    // });
    //
    //
    // const sub_A900_ptr = baseAddr.add(0xA900);  // 替换为你的 sub_A900 地址
    // Interceptor.attach(sub_A900_ptr, {
    //     onEnter(args) {
    //
    //         this.len = args[0].toInt32();
    //         this.a2 = args[1];
    //         if (this.len === 32) {
    //             hook = true;
    //             console.log("[sub_A900] length =", this.len);
    //             console.log("[sub_A900] a2 =", this.a2);
    //         }
    //
    //     },
    //
    //     onLeave(retval) {
    //         if (this.len === 32) {
    //             hook = false;
    //             console.log("[sub_A900] value (hex):\n" + hexdump(this.a2));
    //         }
    //
    //     }
    // });
    //
    //
    // const sub_26430 = baseAddr.add(0x26430);
    // Interceptor.attach(sub_26430, {
    //     onEnter(args) {
    //         console.log("sub_26430 onEnter");
    //         console.log(hexdump(args[0], {length: 0x20}));
    //         console.log('from:', args[1].toInt32());
    //     },
    //     onLeave(retval) {
    //         console.log("sub_25B0C onLeave");
    //     }
    // });
    //
    //
    // const sub_25B0C = baseAddr.add(0x25B0C);
    // Interceptor.attach(sub_25B0C, {
    //     onEnter(args) {
    //         console.log("sub_25B0C onEnter");
    //         console.log(hexdump(args[0], {length: 0x20}));
    //     },
    //     onLeave(retval) {
    //         console.log("sub_25B0C onLeave");
    //     }
    // });
    //

    //
    // let sub_1AFD0_ptr = baseAddr.add(0x1AFD0);
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
    //             console.log("Partial string:", str);
    //         } catch (e) {
    //             console.warn("Invalid UTF-8 at offset", e.offset || "?");
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
            hook_tmp();
        } else {
            setTimeout(waitForLib, 100); // 重试
        }
    };

    waitForLib();

}


setImmediate(hook_system);
