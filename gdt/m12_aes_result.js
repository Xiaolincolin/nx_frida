const libName = "libgdtqone.so";

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


function hook_tmp() {
    const baseAddr = Module.findBaseAddress(libName);
    if (!baseAddr) {
        console.error("❌ 未找到模块:", libName);
        return;
    }

    let urandomFd = -1;

    // hook open
    Interceptor.attach(Module.getExportByName(null, 'open'), {
        onEnter(args) {
            this.path = Memory.readUtf8String(args[0]);
        },
        onLeave(retval) {
            if (this.path === "/dev/urandom" || this.path === "/dev/random") {
                urandomFd = retval.toInt32();
                console.log("[*] /dev/urandom opened => fd =", urandomFd);
            }
        }
    });

    // hook read
    Interceptor.attach(Module.getExportByName(null, 'read'), {
        onEnter(args) {
            this.fd = args[0].toInt32();
            this.buf = args[1];
            this.size = args[2].toInt32();
        },
        onLeave(retval) {
            if (this.fd === urandomFd && this.size === 32) {
                console.log(`[*] read(${this.fd}, ${this.buf}, ${this.size})`);
                const len = Math.min(64, this.size);
                console.log(hexdump(this.buf, {length: len}));
            }
        }
    });

    const sub_1E3C0 = baseAddr.add(0x1E3C0); // md5
    Interceptor.attach(sub_1E3C0, {
        onEnter(args) {
            this.a1 = args[0];
            console.log(`[+] sub_1E3C0 进入：`)
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
            // 记录明文
            const original = Memory.readByteArray(dataPtr, len);
            console.log(`[+] sub_1E3C0 输入(${len} bytes)：\n${hexdump(original, {length: len})}`);
        },
        onLeave(retval) {
            console.log(`[+] sub_1E3C0 输出：\n${hexdump(retval, {length: 16})}`);
        }
    });

    const sub_1E478 = baseAddr.add(0x1E478);
    Interceptor.attach(sub_1E478, {
        onEnter(args) {
            this.result = args[0];
            this.a2 = args[1];
            this.len = args[2].toInt32();

            console.log('[*] sub_1E478 called');
            console.log('    len =', this.len);
            if (this.len > 0 && this.len < 0x1000) {
                try {
                    const data = Memory.readByteArray(this.a2, this.len);
                    console.log('[>] input buffer:');
                    console.log(hexdump(data, {length: this.len}));
                } catch (e) {
                    console.warn('[!] Failed to read input:', e);
                }
            }
        },

        onLeave(retval) {
            try {
                const internalBuf = ptr(this.result).add(24);
                const dump = Memory.readByteArray(internalBuf, 64);
                console.log('[<] internal buffer (result + 24):');
                console.log(hexdump(dump, {length: 64}));
            } catch (e) {
                console.warn('[!] Failed to read internal buffer:', e);
            }
        }
    });


    const sub_2349C = baseAddr.add(0x2349C);
    Interceptor.attach(sub_2349C, {
        onEnter(args) {
            const a1 = args[0]; // a1: __int128* key
            const a2 = args[1].toInt32(); // a2: key 长度
            const a3 = args[2]; // a3: nonce (你可能需要 ptr(args[3]) if it's a pointer)
            const a4 = args[3]; // a4: struct 包含数据长度与指针
            this.a5 = args[4]; // a5

            console.log('[+] sub_2349C called');
            // key 读取 32 字节
            const key = Memory.readByteArray(a1, a2);
            console.log(`[+] Key->（${a2}）:`, hexdump(key, {length: a2}));

            // a4 的结构是长度 + 数据指针
            const tag = a4.readU8();
            console.log(`[+] Data v11 tag: ${tag}`);
            let len, data_str;
            if ((tag & 1) !== 0) {
                len = a4.add(8).readU32();
                data_str = a4.add(16);
            } else {
                len = tag >> 1;
                data_str = a4.add(8);

            }
            console.log(`[+] Data v11: ${len}`);
            console.log('[+] Data:', hexdump(data_str, {length: len}));
        },
        onLeave(retval) {
        }
    });

    const sub_235F4 = baseAddr.add(0x235F4);
    Interceptor.attach(sub_235F4, {
        onEnter(args) {
            const s = args[0];
            const key = args[1];
            const nonce = args[2];
            const i = args[3].toInt32();

            console.log('[+] sub_235F4 called');
            console.log(`[+] s: ${hexdump(s)}`);
            console.log(`[+] key: ${hexdump(key)}`);
            console.log(`[+] nonce: 0x${nonce.toString(16)}`);
            console.log(`[+] i: ${i}`);
        },
        onLeave(retval) {
            console.log('[+] sub_235F4 returned:', hexdump(retval));
        }
    });


    const sub_10028 = baseAddr.add(0x10028);
    Interceptor.attach(sub_10028, {
        onEnter(args) {
            this.outPtr = args[1];
        },
        onLeave(retval) {
            const v41 = Memory.readByteArray(this.outPtr, 16);
            console.log('[+] sub_10028 returned v41:', hexdump(v41));
            const v28 = Memory.readU8(this.outPtr.add(4));
            console.log('    => v28 = 0x' + v28.toString(16));
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

    const sub_111E0 = baseAddr.add(0x111E0);
    Interceptor.attach(sub_111E0, {
        onEnter(args) {
            this.arg0 = args[0].toInt32();
            this.arg1 = args[1].toInt32();
        },
        onLeave(retval) {
            let allow_list = [5606, 5954, 6062, 6062]
            if (allow_list.includes(this.arg1)) {
                const keyStr = Memory.readCString(retval);
                console.log(`[+] sub_111E0(${this.arg0}, ${this.arg1}) 返回字符串: ${keyStr}`);
            }
        }
    });


    const sub_245E4 = baseAddr.add(0x245E4);
    Interceptor.attach(sub_245E4, {
        onEnter(args) {
            this.a1 = args[0];
            this.a2 = args[1].readCString();  // a2 是输出结构体指针
            console.log(`[+] sub_245E4 进入a2 ${this.a2}`)

        },
        onLeave(retval) {
            console.log(`[+] sub_245E4 离开a1\n`, hexdump(this.a1))
        }
    });

    const sub_2500C = baseAddr.add(0x2500C)
    Interceptor.attach(sub_2500C, {
        onEnter(args) {
            this.a1 = args[0];
            this.a2 = args[1];
            console.log(`[+] sub_2500C 进入`)
        },
        onLeave(retval) {
            console.log(`[+] sub_2500C 离开\n`)
            // 读取明文长度
            try {
                const a2 = this.a2;
                const tag = a2.readU64();
                let ptr, len;

                if ((tag & 1) !== 0) {
                    // 指针结构
                    len = a2.add(8).readU64();         // *(a2 + 8)
                    ptr = a2.add(16).readPointer();    // *(a2 + 16)
                } else {
                    // 内联结构
                    len = tag >>> 1;
                    ptr = a2.add(8);                   // inline data
                }

                console.log(`\n[+] sub_2500C 输出结构:`);
                console.log("    tag =", tag.toString());
                console.log("    len =", len);
                console.log("    ptr =", ptr);

                if (len > 0 && len < 0x1000) {
                    const buf = ptr.readByteArray(len);
                    console.log("[+] 内容 Hexdump:");
                    console.log(hexdump(buf, {length: len}));
                } else {
                    console.warn("[!] 输出长度异常，跳过读取");
                }

            } catch (e) {
                console.error("[!] Hook sub_2500C 解析输出失败:", e);
            }
        }
    });

// const sub_1812C = baseAddr.add(0x1812C);  todo params会路过，好多加密会路过，别删
// Interceptor.attach(sub_1812C, {
//     onEnter(args) {
//         this.a1 = args[0];
//         this.a2 = args[1];
//         console.log(`[+] sub_1812C 进入`)
//         // 读取明文长度
//         const flag = this.a2.readU8();
//         let len, dataPtr;
//         if ((flag & 1) === 0) {
//             len = flag >> 1;
//             dataPtr = this.a2.add(8);
//         } else {
//             len = this.a2.add(8).readU32();
//             dataPtr = this.a2.add(16).readPointer();
//         }
//
//         const original = Memory.readByteArray(dataPtr, len);
//         console.log(`[sub_1812C] (${len} bytes): \n${hexdump(original, {length: len})}`);
//
//     },
//     onLeave(retval) {
//         console.log(`[+] sub_1812C 离开\n`)
//     }
// });

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


    const sub_2425C = baseAddr.add(0x2425C);
    Interceptor.attach(sub_2425C, {
        onEnter(args) {
            console.log("sub_2425C onEnter");
            this.data = args[0];
        },
        onLeave(retval) {
            console.log(`[+] sub_2425C 退出 key,iv`, hexdump(this.data, {length: 0x20}));
            // console.log(`[+] sub_2425C 退出 params`, hexdump(this.data.add(32)));
            // console.log(`[+] sub_2425C 退出 sign`, hexdump(this.data.add(104).readPointer()));
            // console.log(`[+] sub_2425C 退出 nonce`, hexdump(this.data.add(80)));
            // console.log(`[+] sub_2425C 退出 extra`, hexdump(this.data.add(128)));
            console.log("sub_2425C onLeave");
        }
    });

    const sub_245A4 = baseAddr.add(0x245A4);
    Interceptor.attach(sub_245A4, {
        onEnter(args) {
            console.log("sub_245A4 onEnter");
            this.data = args[0];
        },
        onLeave(retval) {
            console.log(`[+] sub_245A4 离开key,iv明文`, hexdump(this.data, {length: 0x20}));
            console.log("sub_245A4 onLeave");
            // let ptr = Memory.readPointer(this.out.add(16));
            // console.log(hexdump(ptr));
        }
    });


    const sub_26430 = baseAddr.add(0x26430);
    Interceptor.attach(sub_26430, {
        onEnter(args) {
            console.log("sub_26430 onEnter");
            const data = args[0];
            const flag = args[1].toInt32();
            console.log(`[+] sub_26430 输入,来源：${flag}\n`, hexdump(data, {length: 0x20}));
        },
        onLeave(retval) {
            console.log("sub_26430 onLeave");
            // let ptr = Memory.readPointer(this.out.add(16));
            // console.log(hexdump(ptr));
        }
    });

    const sub_25B0C = baseAddr.add(0x25B0C);
    Interceptor.attach(sub_25B0C, {
        onEnter(args) {
            console.log("sub_25B0C onEnter");
            const data = args[0];
            console.log('[+] sub_25B0C 输入', hexdump(data, {length: 0x20}));
        },
        onLeave(retval) {
            console.log("sub_25B0C onLeave");
            // let ptr = Memory.readPointer(this.out.add(16));
            // console.log(hexdump(ptr));
        }
    });

    const sub_104D0 = baseAddr.add(0x104D0);
    Interceptor.attach(sub_104D0, {
        onEnter(args) {
            console.log("sub_104D0 onEnter");
            const data = args[1];
            const len = args[2].toInt32();
            this.out = args[3];
            console.log('[+] sub_104D0 输入', hexdump(data, {length: len}));
        },
        onLeave(retval) {
            console.log("sub_104D0 onLeave");
            // let ptr = Memory.readPointer(this.out.add(16));
            // console.log(hexdump(ptr));
        }
    });

    const sub_1F0E0_ptr = baseAddr.add(0x1F0E0);
    Interceptor.attach(sub_1F0E0_ptr, {
        onEnter(args) {
            this.a1 = args[0];   // 原始明文结构体
            this.a2 = args[1];   // AES 密钥
            this.a3 = args[2];   // IV 或随机数（可选打印）
            this.a4 = args[3];   // 输出结构体

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


    const sub_1AFD0_ptr = baseAddr.add(0x1AFD0);
    Interceptor.attach(sub_1AFD0_ptr, {
        onEnter(args) {

        }, onLeave(retval) {
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


// const sub_1F45C_ptr = baseAddr.add(0x1F45C);
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
// const sub_104D0 = baseAddr.add(0x104D0);
// Interceptor.attach(sub_104D0, {
//     onEnter(args) {
//         console.log("sub_104D0 onEnter");
//         // const data = args[1];
//         // const len = args[2].toInt32();
//         // this.out = args[3];
//         // console.log(hexdump(data, {length: len}));
//     },
//     onLeave(retval) {
//         console.log("sub_104D0 onLeave");
//         // let ptr = Memory.readPointer(this.out.add(16));
//         // console.log(hexdump(ptr));
//     }
// });
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
