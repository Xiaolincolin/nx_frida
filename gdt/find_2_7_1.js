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
            // const backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE)
            //     .map(addr => DebugSymbol.fromAddress(addr).toString())
            //     .join("\n");
            // console.log("[Call Stack]\n" + backtrace);

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
            // const backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE)
            //     .map(addr => DebugSymbol.fromAddress(addr).toString())
            //     .join("\n");
            // console.log("[Call Stack]\n" + backtrace);

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
                if (!str) return;
                console.log("[sub_1AFD0] string:", str);
            } catch (e) {
                console.warn("[sub_1AFD0] Invalid UTF-8 at offset", e.offset || "?");
            }
        }
    });
}


function hook_1CCBC(baseAddr) {
    let sub_1CCBC = baseAddr.add(0x1CCBC);
    Interceptor.attach(sub_1CCBC, {
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
            if (len === 0) {
                return
            }
            const original = Memory.readByteArray(dataPtr, len);
            console.log(`[sub_1CCBC] enter (${len} bytes): \n${hexdump(original, {length: len})}`);
            const backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE)
                .map(addr => DebugSymbol.fromAddress(addr).toString())
                .join("\n");
            console.log("[Call Stack]\n" + backtrace);
        },

        onLeave(retval) {

        }
    });
}

function hook_17f2c(baseAddr) {
    let sub_17F2C = baseAddr.add(0x17f2c);
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

function hook_14A50(baseAddr) {
    let sub_14A50 = baseAddr.add(0x14A50);
    Interceptor.attach(sub_14A50, {
        onEnter(args) {
            console.log('enter sub_14A50')
            this.a1 = this.context.x8;
        },

        onLeave(retval) {
            console.log('onLeave sub_14A50');
            console.log('result->', retval.readCString())
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
            const flag = this.a1.readU8();
            let len, dataPtr;
            if ((flag & 1) === 0) {
                len = flag >> 1;
                dataPtr = this.a1.add(8);
            } else {
                len = this.a1.add(8).readU32();
                dataPtr = this.a1.add(24).readPointer();
            }
            if (len === 0) {
                return
            }
            const original = Memory.readByteArray(dataPtr, len);
            console.log(`[sub_202AC] retval (${len} bytes): \n${hexdump(original, {length: len})}`);
        }
    });
}

function hook_sha256_update(baseAddr) {
    // 替换为 sub_1FEDC 的实际地址
    const sub_1FC60 = baseAddr.add(0x1FC60);

    Interceptor.attach(sub_1FC60, {
        onEnter(args) {
            const resultPtr = args[0];
            const srcPtr = args[1];
            const len = args[2].toInt32();

            console.log("[*] SHA256 Update Input");
            console.log("    Length:", len);
            if (len > 0 && len < 1024) {
                console.log("    Data:", Memory.readByteArray(srcPtr, len));
            }

            this.resultPtr = resultPtr;
        },
        onLeave(retval) {
            const currentBits = Memory.readU32(this.resultPtr);
            console.log("[+] SHA256 Total Bits:", currentBits);
        }
    });


}

function hook_SHA256_Final(baseAddr) {
    const target = baseAddr.add(0x1FD3C); // 根据你的 baseAddr 调整偏移

    Interceptor.attach(target, {
        onEnter(args) {
            this.statePtr = args[0];
            this.outputPtr = args[1];
        },
        onLeave(retval) {
            const digestBytes = Memory.readByteArray(this.outputPtr, 32);
            console.log('[+] SHA256 Digest:', hexdump(digestBytes, {length: 32}));
        }
    });
}

function hook_sha256(baseAddr) {

    const sub_1FC60 = baseAddr.add(0x1FC60); // 根据你的 baseAddr 调整偏移
    const sub_1FEDC = baseAddr.add(0x1FEDC); // 根据你的 baseAddr 调整偏移
    const sub_1FD3C = baseAddr.add(0x1FD3C); // 根据你的 baseAddr 调整偏移

    // 1. Hook 输入数据
    Interceptor.attach(sub_1FC60, {
        onEnter: function (args) {
            console.log("\n[+] sub_1FC60 Input (Length:", args[2].toInt32(), ")");
            console.log(hexdump(args[1], {length: args[2].toInt32()}));
        }
    });

    // 2. Hook 压缩函数
    Interceptor.attach(sub_1FEDC, {
        onEnter: function (args) {
            this.ctx = args[0];
            this.input = args[1];
            console.log('[+] SHA256 Block Input:');
            console.log(hexdump(this.input, {length: 64}));
        },
        onLeave: function (retval) {
            // 打印 context 中的 state[8]
            console.log('[+] SHA256 state after block:');
            const state = this.ctx.add(8); // 假设 ctx+8 是 state 起始
            let digest = [];
            for (let i = 0; i < 8; i++) {
                const word = Memory.readU32(state.add(i * 4));
                digest.push(('00000000' + word.toString(16)).slice(-8));
            }
            console.log('Digest (intermediate):', digest.join(''));
        }
    });


    // 3. Hook Final 函数
    Interceptor.attach(sub_1FD3C, {
        onEnter: function (args) {
            this.output = args[1]; // output digest ptr
        },
        onLeave: function (retval) {
            console.log("[+] Final SHA256 digest:");
            console.log(hexdump(this.output, {length: 32}));
        }
    });

}

function hook_tmp(baseAddr) {

    let sub_3F1E4 = baseAddr.add(0x3F214);
    Interceptor.attach(sub_3F1E4, {
        onEnter(args) {
            console.log('onEnter sub_3F1E4')
            let x8 = this.context.x27;   // 原始明文结构体
            console.log(`[sub_3F1E4] : \n${hexdump(x8, {length: 32})}`);
        },

        onLeave(retval) {

        }
    });

    // let sub_3EF68 = baseAddr.add(0x3EF68);
    // Interceptor.attach(sub_3EF68, {
    //     onEnter(args) {
    //         console.log('onEnter sub_3EF68')
    //         let x22 = this.context.x22;   // 原始明文结构体
    //         console.log(`[sub_3EF68] : \n${hexdump(x22, {length: 32})}`);
    //     },
    //
    //     onLeave(retval) {
    //
    //     }
    // });

    //
    // let sub_3EF98 = baseAddr.add(0x3EF98);
    // Interceptor.attach(sub_3EF98, {
    //     onEnter(args) {
    //         this.a1 = this.context.x0;   // 原始明文结构体
    //         const flag = this.a1.readU8();
    //         let len, dataPtr;
    //         if ((flag & 1) === 0) {
    //             len = flag >> 1;
    //             dataPtr = this.a1.add(8);
    //         } else {
    //             len = this.a1.add(8).readU32();
    //             dataPtr = this.a1.add(16).readPointer();
    //         }
    //         if (len === 0) {
    //             return
    //         }
    //         const original = Memory.readByteArray(dataPtr, len);
    //         console.log(`[sub_3EF98] enter (${len} bytes): \n${hexdump(original, {length: len})}`);
    //     },
    //
    //     onLeave(retval) {
    //
    //     }
    // });
}

function hook_main(libName) {
    const baseAddr = Module.findBaseAddress(libName);
    if (!baseAddr) {
        console.error("❌ 未找到模块:", libName);
        return;
    }
    console.log('baseadd', baseAddr);
    hook_tmp(baseAddr);
    hook_params_aes(baseAddr);
    hook_body(baseAddr);
    hook_17f2c(baseAddr);
    hook_1CCBC(baseAddr);
    // hook_14A50(baseAddr);
    hook_202AC(baseAddr);
    // hook_sha256_update(baseAddr);
    // hook_SHA256_Final(baseAddr);
    // hook_sha256(baseAddr);
}

function hook_system() {
    const libname = "libgdtqone.so";

    const waitForLib = () => {
        const m = Process.findModuleByName(libname);
        if (m) {
            console.log("🧬 Found", libname, "at", m.base);
            hook_main(libname);
        } else {
            setTimeout(waitForLib, 100); // 重试
        }
    };

    waitForLib();

}


setImmediate(hook_system);
