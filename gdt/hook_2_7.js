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

function hook_sha256_dig(baseAddr) {
    const sub_1FEDC = baseAddr.add(0x1FEDC);
    Interceptor.attach(sub_1FEDC, {
        onEnter(args) {
            this.result_ptr = args[0];
            this.input_ptr = args[1];

            console.log('[*] SHA256 Compress Start');
            console.log('result_ptr:', this.result_ptr);
            console.log('input_ptr:', this.input_ptr);

            const state = Memory.readByteArray(this.result_ptr, 32);
            const block = Memory.readByteArray(this.input_ptr, 64);

            if (state) {
                console.log('[-] Initial State:');
                console.log(hexdump(state, {offset: 0, length: 32}));
            } else {
                console.log('[!] State read failed');
            }

            if (block) {
                console.log('[-] Input Block:');
                console.log(hexdump(block, {offset: 0, length: 64}));
            } else {
                console.log('[!] Block read failed');
            }
        },
        onLeave(retval) {
            const state_after = Memory.readByteArray(this.result_ptr, 32);
            if (state_after) {
                console.log('[-] Output State:');
                console.log(hexdump(state_after, {offset: 0, length: 32}));
            } else {
                console.log('[!] Output read failed');
            }
        }
    });

}

function hook_17F2C(baseAddr) {
    let sub_17F2C = baseAddr.add(0x17F2C);
    Interceptor.attach(sub_17F2C, {
        onEnter(args) {
            const a2 = args[1];
            let valueStr = '(unreadable)';
            try {
                const flag = a2.readU8(); // 第一字节可能是 flag
                if ((flag & 1) === 0) {
                    // 低位为 0，表示内联字符串，读取 a2 + 0x10
                    const strPtr = a2.add(8);
                    valueStr = strPtr.readUtf8String();
                } else {
                    // 高位为 1，表示堆分配，指针在 a2 + 0x10
                    const heapPtr = a2.add(8);
                    valueStr = heapPtr.readUtf8String();
                }
            } catch (e) {
                valueStr = `(error reading: ${e})`;
            }
            console.log(`[sub_17F2C] a2 @ ${a2} → value: "${valueStr}"`);
        }
    });
}

function hook_sha256(baseAddr) {
    // 替换为 sub_1FEDC 的实际地址
    const sub_1FC60 = baseAddr.add(0x1FC60);

    Interceptor.attach(sub_1FC60, {
        onEnter(args) {
            this.ctx = args[0];
            const src = args[1];
            const len = args[2].toInt32();

            console.log('[*] SHA256 Update');
            console.log('Length:', len);

            if (len > 0 && src) {
                const buf = Memory.readByteArray(src, len);
                if (buf) {
                    console.log('buf\n', hexdump(buf, {offset: 0, length: len}));
                } else {
                    console.log('buf is null');
                }

            }
        },
        onLeave(retval) {
            const statePtr = this.ctx.add(4); // ctx + 4 * 1 (跳过 bit count)
            const state = [];

            for (let i = 0; i < 8; i++) {
                state.push(Memory.readU32(statePtr.add(i * 4)).toString(16).padStart(8, '0'));
            }

            console.log('[-] Output SHA256 State:');
            console.log(state.join(' '));
        }
    });


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

function hook_1C514(baseAddr) {
    const sub_1C514 = baseAddr.add(0x1C514);
    Interceptor.attach(sub_1C514, {
        onEnter(args) {
            console.log('enter sub_1C514');
        },
        onLeave(retval) {
            console.log('leave sub_1C514 v7->', retval)
            var ptr_to_str = Memory.readPointer(retval.add(24 + 56)); // result[2]
            console.log('sub_1C514 retval Content =', Memory.readUtf8String(ptr_to_str));
        }
    });
}


function hook_1BF8C(baseAddr, offset) {
    const target = baseAddr.add(offset);
    Interceptor.attach(target, {
        onEnter(args) {
            console.log('enter sub_1BF8C');
            this.keyPtr = args[2].add(1);
            try {
                const keyStr = Memory.readUtf8String(this.keyPtr);
                console.log('[sub_1BF8C] Searching key (string):', keyStr);
            } catch (e) {
                console.log('[sub_1BF8C] Searching key (raw ptr):', this.keyPtr);
            }
        },
        onLeave(retval) {
            console.log('leave sub_1BF8C')
            const v6 = retval;
            const v7 = Memory.readPointer(v6); // *v6，就是sub_1C514里的v7
            if (!v7.isNull()) {
                console.log('[*] sub_1BF8C returns v6 =', v6, ' => *v6 (v7) =', v7);
                var ptr_to_str = Memory.readPointer(v7.add(24 + 56)); // result[2]
                console.log('[*] v7+80 field:', Memory.readUtf8String(ptr_to_str));
            }
        }
    });
}

function hook_tmp(baseAddr) {
    // Interceptor.attach(baseAddr.add(0x4972C), {
    //     onLeave(retval) {
    //         console.log('[sub_4972C] allocated @', retval);
    //     }
    // });

    // const target = baseAddr.add(0x1C54C);
    // Interceptor.attach(target, {
    //     onEnter(args) {
    //         var x0 = this.context.x0;
    //         var x19 = Memory.readPointer(x0);
    //         console.log('[*] LDR X19, [X0] =', x19);
    //         if (x19.isNull()) {
    //             console.log('[*] Will jump to loc_1C55C');
    //         } else {
    //             console.log('[*] Continue execution');
    //         }
    //     }
    // });

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
    // hook_has_enter(baseAddr, 0x1BF8C);
    // hook_has_enter(baseAddr, 0x4972C);
    // hook_has_enter(baseAddr, 0xB3A8)
    // hook_has_enter(baseAddr, 0x1BE30)
    hook_tmp(baseAddr);
    hook_1BF8C(baseAddr, 0x1BF8C);
    hook_1C514(baseAddr);
    hook_17DEC(baseAddr);
    hook_sha256(baseAddr);
    hook_params_aes(baseAddr);
    // hook_17F2C(baseAddr);
    // hook_sha256_dig(baseAddr);

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
