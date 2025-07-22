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

function hook_B3A8(baseAddr) {
    const sub_B3A8_addr = baseAddr.add(0xB3A8);
    Interceptor.attach(sub_B3A8_addr, {
        onEnter(args) {
            console.log('enter sub_B3A8')
            this.result = args[0];
            this.a2 = args[1];
            const flag = this.a2.readU8();
            let strPtr, length, str;

            if ((flag & 1) === 0) {
                // 短字符串，直接读取结构体中字符串（result+8）
                strPtr = this.a2.add(8);
                str = strPtr.readUtf8String();
                length = str.length;
            } else {
                // 堆分配的字符串
                length = this.a2.add(8).readU64();
                strPtr = this.a2.add(16).readPointer();
                str = strPtr.readUtf8String();
            }
            console.log(`[sub_B3A8] enter string: "${str}" (len=${length})`);

        },
        onLeave(retval) {

            try {
                const result = this.result;
                const flag = result.readU8();
                let strPtr, length, str;

                if ((flag & 1) === 0) {
                    // 短字符串，直接读取结构体中字符串（result+8）
                    strPtr = result.add(8);
                    str = strPtr.readUtf8String();
                    length = str.length;
                } else {
                    // 堆分配的字符串
                    length = result.add(8).readU64();
                    strPtr = result.add(16).readPointer();
                    str = strPtr.readUtf8String();
                }

                console.log(`[sub_B3A8] Result string: "${str}" (len=${length})`);
            } catch (e) {
                console.error('[sub_B3A8] Error:', e);
            }
            console.log('leave sub_B3A8')
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

function hook_111E0(baseAddr) {
    const sub_111E0 = baseAddr.add(0x111E0);
    Interceptor.attach(sub_111E0, {
        onEnter(args) {
            this.arg0 = args[0].toInt32();
            this.arg1 = args[1].toInt32();
        },
        onLeave(retval) {
            // let allow_list = [5606, 5954, 6062, 6062, 9152]
            // if (allow_list.includes(this.arg1)) {
            //     const keyStr = Memory.readCString(retval);
            //     console.log(`[+] sub_111E0(${this.arg0}, ${this.arg1}) 返回字符串: ${keyStr}`);
            // }
            const keyStr = Memory.readCString(retval);
            console.log(`[+] sub_111E0(${this.arg0}, ${this.arg1}) 返回字符串: ${keyStr}`);
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

    const sub_1FE60 = baseAddr.add(0x1FE60);
    const sub_1FC60 = baseAddr.add(0x1FC60); // 根据你的 baseAddr 调整偏移
    const sub_1FEDC = baseAddr.add(0x1FEDC); // 根据你的 baseAddr 调整偏移
    const sub_1FD3C = baseAddr.add(0x1FD3C); // 根据你的 baseAddr 调整偏移


    Interceptor.attach(sub_1FE60, {
        onEnter: function (args) {
            this.a3 = args[2];
            console.log("\n[+] sub_1FE60 Input (Length:", args[1].toInt32(), ")");
            console.log(hexdump(args[0], {length: args[1].toInt32()}));
            const backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE)
                .map(addr => DebugSymbol.fromAddress(addr).toString())
                .join("\n");
            console.log("[Call Stack]\n" + backtrace);

        },
        onLeave: function (retval) {
            console.log("[+] sub_1FE60 Output ");
            console.log(hexdump(this.a3, {length: 32}));
        }
    });


    //1. Hook 输入数据
    Interceptor.attach(sub_1FC60, {
        onEnter: function (args) {
            console.log("\n[+] sub_1FC60 Input (Length:", args[2].toInt32(), ")");
            console.log(hexdump(args[1], {length: args[2].toInt32()}));
            // const backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE)
            //     .map(addr => DebugSymbol.fromAddress(addr).toString())
            //     .join("\n");
            // console.log("[Call Stack]\n" + backtrace);
        }
    });

    // // 2. Hook 压缩函数
    // Interceptor.attach(sub_1FEDC, {
    //     onEnter: function (args) {
    //         console.log("\n[+] SHA-256 Block Processing Start");
    //
    //         // Log input block (a2)
    //         const block = args[1];
    //         console.log("Input Block (hex):");
    //         console.log(hexdump(block, {length: 64})); // 64 bytes = 512 bits
    //
    //         // Log initial ctx (result)
    //         const ctx = args[0];
    //         console.log("Initial Hash State (a-h):");
    //         for (let i = 0; i < 8; i++) {
    //             const val = ctx.add(8 + i * 4).readU32();
    //             console.log(`  ${String.fromCharCode(97 + i)} = 0x${val.toString(16).padStart(8, '0')}`);
    //         }
    //     },
    //     onLeave: function (retval) {
    //         const ctx = this.context.x0; // result (ctx)
    //         console.log("Final Hash State (a-h):");
    //         for (let i = 0; i < 8; i++) {
    //             const val = ctx.add(8 + i * 4).readU32();
    //             console.log(`  ${String.fromCharCode(97 + i)} = 0x${val.toString(16).padStart(8, '0')}`);
    //         }
    //         console.log("[+] SHA-256 Block Processing End\n");
    //     }
    // });


    // 3. Hook Final 函数
    let end_add = baseAddr.add(0x17f2c)
    Interceptor.attach(sub_1FD3C, {
        onEnter: function (args) {
            this.output = args[1]; // output digest ptr
            this.ctx = args[0];
            console.log('enter sub_1FD3C~~~~~');
            this.tid = Process.getCurrentThreadId();
        },
        onLeave: function (retval) {
            console.log("[+] sub_1FD3C Final SHA256 digest:");
            console.log(hexdump(this.output, {length: 32}));
            // stk_trace(this.tid, baseAddr, end_add);
        }
    });

}

function hook_tmp(baseAddr) {
    // let target = baseAddr.add(0x422E4);
    // Interceptor.attach(target, {
    //     onEnter(args) {
    //         console.log('onEnter target')
    //         this.a1 = args[1];   // 原始明文结构体
    //         // console.log(`[target enter] : \n${hexdump(this.a1, {length: 32})}`);
    //     },
    //
    //     onLeave(retval) {
    //         console.log(`[target retval] : \n${hexdump(this.a1, {length: 64})}`);
    //
    //     }
    // });

    // const sub_AF08_ptr = baseAddr.add(0xAF08);
    // Interceptor.attach(sub_AF08_ptr, {
    //     onEnter(args) {
    //         const strPtr = args[1];
    //         try {
    //             const s = strPtr.readUtf8String();
    //             console.log(`[sub_AF08] preparing string: "${s}"`);
    //             if (s === "7") {
    //                 const backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE)
    //                     .map(addr => DebugSymbol.fromAddress(addr).toString())
    //                     .join("\n");
    //                 console.log("[Call Stack]\n" + backtrace);
    //             }
    //         } catch (e) {
    //         }
    //     }
    // });

    // let sub_3EF68 = baseAddr.add(0x3EF68);
    // Interceptor.attach(sub_3EF68, {
    //     onEnter(args) {
    //         console.log('onEnter sub_3EF68')
    //         let x19 = this.context.x19.add(0x1D8).readPointer();
    //         console.log(x19)
    //         console.log(`[sub_3EF68 x19] : \n${hexdump(x19, {length: 32})}`);
    //
    //         let x22 = this.context.x22;   // 原始明文结构体
    //         console.log(x22)
    //         console.log(`[sub_3EF68 x22] : \n${hexdump(x22, {length: 32})}`);
    //     },
    //
    //     onLeave(retval) {
    //
    //     }
    // });

    // let sub_3F928 = baseAddr.add(0x3F928);
    // Interceptor.attach(sub_3F928, {
    //     onEnter(args) {
    //         console.log('index sub_3F928')
    //         let x19 = this.context.x8;
    //         console.log(x19)
    //         // console.log(`[sub_3F208 x19] : \n${hexdump(x19, {length: 32})}`);
    //     }
    // });

    let sub_3F92C = baseAddr.add(0x3F92C);
    Interceptor.attach(sub_3F92C, {
        onEnter(args) {
            let x8 = this.context.x8;
            console.log('index ori sub_3F92C: ', x8)
            console.log('index sub_3F92C: ', x8 & 0x1f)
            // console.log(`[sub_3F208 x19] : \n${hexdump(x19, {length: 32})}`);
        }
    });

    let sub_3F93C = baseAddr.add(0x3F93C);
    Interceptor.attach(sub_3F93C, {
        onEnter(args) {
            let x8 = this.context.x8;
            console.log('value sub_3F93C: ', x8)
        }
    });


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

function formatInstruction(instr, baseAddr) {
    const addr = instr.address;
    const offset = addr.sub(baseAddr);

    let mnemonic = '';
    let opStr = '';
    try {
        mnemonic = instr.mnemonic || '';
        opStr = instr.opStr || '';
    } catch (e) {
        // 忽略错误，兼容旧设备
    }

    const isCall = ['bl', 'blx', 'call'].includes(mnemonic.toLowerCase());
    const prefix = isCall ? '⚡️ CALL >>> ' : '    ';

    return `${prefix}[${offset}] ${addr}:\t${mnemonic.padEnd(8)} ${opStr}`;
}

function stk_trace(tid, baseAddr, end_addr) {
    Stalker.follow(tid, {
        transform: (iterator) => {
            let instruction = iterator.next();
            const startAddress = instruction.address;
            const inRange = startAddress.compare(baseAddr) >= 0 && startAddress.compare(end_addr) < 0;
            while (instruction !== null) {
                if (inRange) {
                    console.log(formatInstruction(instruction, baseAddr));
                }
                iterator.keep();
                instruction = iterator.next();
            }
        }
    });
}

function hook_sub_3DD80(baseAddr) {
    const sub_3DD80 = baseAddr.add(0x3DD80);
    const end_add = baseAddr.add(0x40BA0);
    Interceptor.attach(sub_3DD80, {
        onEnter(args) {
            console.log('enter sub_3DD80');
            // this.tid = Process.getCurrentThreadId();
            // stk_trace(this.tid, baseAddr, end_add);
        },
        onLeave(retval) {
            console.log('leave sub_3DD80')
            // Stalker.unfollow(this.tid);
            // Stalker.garbageCollect();
        }
    })
}

function hook_sub_10394(baseAddr) {
    const sub_10394 = baseAddr.add(0x10394);
    Interceptor.attach(sub_10394, {
        onEnter(args) {
            console.log('enter sub_10394');
            this.a3 = args[2];
        },
        onLeave(retval) {
            console.log('leave sub_10394')
            console.log(hexdump(this.a3, {length: 32}))
        }
    })
}

function hook_main(libName) {
    const baseAddr = Module.findBaseAddress(libName);
    if (!baseAddr) {
        console.error("❌ 未找到模块:", libName);
        return;
    }
    console.log('baseadd', baseAddr);
    hook_tmp(baseAddr);
    // hook_params_aes(baseAddr);
    // hook_body(baseAddr);
    hook_17f2c(baseAddr);
    hook_1CCBC(baseAddr);
    // hook_14A50(baseAddr);
    // hook_202AC(baseAddr);
    // hook_sha256_update(baseAddr);
    // hook_SHA256_Final(baseAddr);
    // hook_sha256(baseAddr);
    // hook_B3A8(baseAddr);
    hook_sub_10394(baseAddr);
    // hook_sub_3DD80(baseAddr);
}

function hook_system() {
    const libname = "libgdtqone.so";

    const waitForLib = () => {
        const m = Process.findModuleByName(libname);
        if (m) {
            console.log("🧬 Found", libname, "at", m.base);
            hook_main(libname);
        } else {
            console.log('not found libgdtqone.so')
            setTimeout(waitForLib, 100); // 重试
        }
    };

    waitForLib();

}


setImmediate(hook_system);
