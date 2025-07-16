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

function hook_235F4_bak(baseAddr) {
    const sub_235F4 = baseAddr.add(0x235F4);

    // 准备参数
    const key = Memory.alloc(32);
    const resultBuf = Memory.alloc(64); // 16 * 4-byte int

    // 写入 key 数据
    const keyBytes = [
        0xbe, 0x3b, 0x81, 0xf3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00
    ];
    for (let i = 0; i < 32; i++) {
        key.add(i).writeU8(keyBytes[i]);
    }

    // nonce 和 counter
    const nonce = ptr("0x65a4e57fef44a2a3");  // 64-bit
    const counter = ptr(0x0);  // 从 0 开始

    // 调用 native 函数
    const native_func = new NativeFunction(sub_235F4, 'pointer', ['pointer', 'pointer', 'pointer', 'pointer']);
    native_func(resultBuf, key, nonce, counter);

    // 打印结果
    console.log("[*] Salsa20 keystream output:");
    console.log(hexdump(resultBuf, {
        length: 64,
    }));

}

function hook_235F4(baseAddr) {
    const sub_235F4_addr = baseAddr.add(0x235F4);
    Interceptor.attach(sub_235F4_addr, {
        onEnter(args) {
            this.resultPtr = args[0]; // int *result
            this.keyPtr = args[1];    // __int128 *a2
            this.nonce = args[2];     // __int64 a3
            this.counter = args[3];   // __int64 a4

            console.log("\n==================== sub_235F4 ====================");
            console.log("[*] Key (a2, 32 bytes):");
            console.log(hexdump(this.keyPtr, {length: 32, header: false, ansi: false}));

            const keyBytes = Memory.readByteArray(this.keyPtr, 32);
            const keyHex = Array.from(new Uint8Array(keyBytes)).map(b => `0x${b.toString(16).padStart(2, '0')}`);
            console.log("key[] = {\n  " + keyHex.join(', ').replace(/(.{60})/g, '$1\n  ') + "\n}");

            console.log(`[*] Nonce (a3): 0x${this.nonce.toString(16).padStart(16, '0')}`);
            console.log(`[*] Counter (a4): 0x${this.counter.toString(16).padStart(16, '0')}`);
        },

        onLeave(retval) {
            console.log("[*] Keystream (result, 64 bytes):");
            console.log(hexdump(this.resultPtr, {length: 64, header: false, ansi: false}));

            const buf = Memory.readByteArray(this.resultPtr, 64);
            const bytes = Array.from(new Uint8Array(buf));

            // Print as uint8_t[]
            const byteHex = bytes.map(b => `0x${b.toString(16).padStart(2, '0')}`);
            console.log("keystream[] = {\n  " + byteHex.join(', ').replace(/(.{60})/g, '$1\n  ') + "\n}");

            // Print as uint32_t word[16]
            // console.log("result[16] = {");
            // for (let i = 0; i < 16; i++) {
            //     const word = bytes[i * 4] | (bytes[i * 4 + 1] << 8) | (bytes[i * 4 + 2] << 16) | (bytes[i * 4 + 3] << 24);
            //     console.log(`  0x${word.toString(16).padStart(8, '0')},`);
            // }
            // console.log("};");
        }
    });

}

function hook_2349c(baseAddr) {
    const sub_2349C = baseAddr.add(0x2349C);
    Interceptor.attach(sub_2349C, {
        onEnter(args) {
            const a1 = args[0]; // a1: __int128* key
            const a2 = args[1].toInt32(); // a2: key 长度
            const a3 = args[2]; // a3: nonce (你可能需要 ptr(args[3]) if it's a pointer)
            const a4 = args[3]; // a4: struct 包含数据长度与指针
            console.log('====', args[4])
            this.a5 = this.context.x8;
            console.log('[+] sub_2349C called');
            // key 读取 32 字节
            const key = Memory.readByteArray(a1, a2);
            console.log(`[+] sub_2349C a1->（${a2}）:`, hexdump(key, {length: a2}));

            console.log(`[+] sub_2349C a3->:`, a3.toString(16));


            // a4 的结构是长度 + 数据指针
            const tag = a4.readU8();
            let len, data_str;
            if ((tag & 1) !== 0) {
                len = a4.add(8).readU8();
                data_str = a4.add(16);
                console.log('2349c走堆内存')
            } else {
                len = tag >> 1;
                data_str = a4.add(1);
                console.log('2349c走inline')
            }
            const keyBytes = Memory.readByteArray(data_str, len);
            const keyHex = Array.from(new Uint8Array(keyBytes)).map(b => `0x${b.toString(16).padStart(2, '0')}`);
            console.log(`[+] sub_2349C a4(${len}) bytes:`, hexdump(data_str, {length: len}));
            console.log("plaintext[] = {\n  " + keyHex.join(', ').replace(/(.{60})/g, '$1\n  ') + "\n}");
        },
        onLeave(retval) {
            console.log('[+] sub_2349C leave:');
            console.log(hexdump(this.a5, {length: 32}))
            console.log('v27 =>value:', this.a5.readU8());

            console.log('a5 format');
            const tag = this.a5.readU8();
            console.log('a5 tag:', tag);

            let len, data_str;
            if ((tag & 1) !== 0) {
                len = this.a5.add(8).readU8();
                data_str = this.a5.add(16);
            } else {
                len = tag >> 1;
                data_str = this.a5.add(8);
            }
            const keyBytes = Memory.readByteArray(data_str, len);
            console.log(hexdump(keyBytes, {length: len}))
            console.log('a5 format final');
        }
    });
}

function hook_sign(baseAddr) {
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
}

function hook_md5_encrypt(baseAddr) {
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
}

function hook_sign_md5(baseAddr) {
    const sub_10028 = baseAddr.add(0x10028);
    Interceptor.attach(sub_10028, {
        onEnter(args) {
            console.log('enter sub_10028')
            let a1 = args[0];
            this.outPtr = args[1];
            const flag = a1.readU8();
            let len, dataPtr;
            if ((flag & 1) === 0) {
                len = flag >> 1;
                dataPtr = a1.add(8);
            } else {
                len = a1.add(8).readU32();
                dataPtr = a1.add(16).readPointer();
            }
            // 记录明文
            const original = Memory.readByteArray(dataPtr, len);
            console.log(`[+] sub_10028 输入(${len} bytes)：\n${hexdump(original, {length: len})}`);
        },
        onLeave(retval) {
            const v41 = Memory.readByteArray(this.outPtr, 16);
            console.log('[+] sub_10028 returned v41:', hexdump(v41));
            const v28 = Memory.readU8(this.outPtr.add(4));
            console.log('    => v28 = 0x' + v28.toString(16));
        }
    });
}

function hook_rsa_key_common(baseAddr) {
    const sub_111E0 = baseAddr.add(0x111E0);
    Interceptor.attach(sub_111E0, {
        onEnter(args) {
            this.arg0 = args[0].toInt32();
            this.arg1 = args[1].toInt32();
        },
        onLeave(retval) {
            let allow_list = [5606, 5954, 6062]
            if (allow_list.includes(this.arg1)) {
                const keyStr = Memory.readCString(retval);
                console.log(`[+] sub_111E0(${this.arg0}, ${this.arg1}) 返回字符串: ${keyStr}`);
            }
            // const keyStr = Memory.readCString(retval);
            // console.log(`[+] sub_111E0(${this.arg0}, ${this.arg1}) 返回字符串: ${keyStr}`);
        }
    });
}

function hook_aes_encrypt(baseAddr) {
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
}

function aes_key_iv() {
    let urandomFd = -1;
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

function hook_1d6f0(baseAddr) {
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
}

function hook_20720(baseAddr) {

    const sub_20720 = baseAddr.add(0x20720);
    Interceptor.attach(sub_20720, {
        onEnter(args) {
            console.log('sub_20720 enter')
            this.a1 = args[0];
            this.a2 = args[1];
            this.a3 = this.context.x8;

            // 打印 a1
            const flag1 = Memory.readU8(this.a1);
            if ((flag1 & 1) === 1) {
                this.len1 = Memory.readU64(this.a1.add(1)).toNumber();
                this.ptr1 = Memory.readPointer(this.a1.add(2));
            } else {
                this.len1 = flag1 >> 1;
                this.ptr1 = this.a1.add(1);
            }

            // 打印 a2
            const flag2 = Memory.readU8(this.a2);
            if ((flag2 & 1) === 1) {
                this.len2 = Memory.readU64(this.a2.add(1)).toNumber();
                this.ptr2 = Memory.readPointer(this.a2.add(2));
            } else {
                this.len2 = flag2 >> 1;
                this.ptr2 = this.a2.add(1);
            }

            console.log('[sub_20720] Called');
            console.log(`[+] a1.len = ${this.len1}`);
            console.log(`[+] a1.data = ${this.ptr1}`);
            console.log(hexdump(this.ptr1, {length: this.len1}));

            console.log(`[+] a2.len = ${this.len2}`);
            console.log(`[+] a2.data = ${this.ptr2}`);
            console.log(hexdump(this.ptr2, {length: this.len2}));
        },

        onLeave(retval) {
            const flag3 = Memory.readU64(this.a3); // *a3
            const isHeap = (flag3 & 1) === 1;
            let len3, data3;

            if (isHeap) {
                len3 = Memory.readU64(this.a3.add(8)).toNumber();
                data3 = Memory.readPointer(this.a3.add(16));
            } else {
                len3 = flag3 >> 1;
                data3 = this.a3.add(8);
            }

            console.log(`[+] a3.len = ${len3}`);
            console.log(`[+] a3.data = ${data3}`);
            console.log(hexdump(data3, {length: len3}));

            console.log(`[+] sub_20720 returned: ${retval}`);
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
            // const flag = this.a1.readU8();
            // let len, dataPtr;
            // if ((flag & 1) === 0) {
            //     len = flag >> 1;
            //     dataPtr = this.a1.add(8);
            // } else {
            //     len = this.a1.add(8).readU32();
            //     dataPtr = this.a1.add(16).readPointer();
            // }
            // const original = Memory.readByteArray(dataPtr, len);
            // console.log(`[hook_43BDC]01 enter Plaintext (${len} bytes): \n${hexdump(original, {length: len})}`);

            // const backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE)
            //     .map(addr => DebugSymbol.fromAddress(addr).toString())
            //     .join("\n");
            // console.log("[Call Stack]\n" + backtrace);
        },

        onLeave(retval) {
        }
    });
}

function hook_1BE30(baseAddr) {
    const sub_1BE30 = baseAddr.add(0x1BE30);
    Interceptor.attach(sub_1BE30, {
        onEnter(args) {
            console.log('enter sub_1BE30')
            var ptr_to_str = Memory.readPointer(args[4].add(24 + 56)); // result[2]
            console.log('sub_1BE30 retval Content =', Memory.readUtf8String(ptr_to_str));

        },
        onLeave(retval) {
            console.log('leave sub_1BE30')

        }
    });
}

function hook_1C514(baseAddr) {
    const sub_1C514 = baseAddr.add(0x1C514);
    Interceptor.attach(sub_1C514, {
        onEnter(args) {
            console.log('enter sub_1C514')

        },
        onLeave(retval) {
            console.log('leave sub_1C514')
            var ptr_to_str = Memory.readPointer(retval.add(24 + 56)); // result[2]
            console.log('sub_1C514 retval Content =', Memory.readUtf8String(ptr_to_str));
        }
    });
}

function hook_sub_17DEC(baseAddr) {
    const sub_17DEC = baseAddr.add(0x17DEC);
    Interceptor.attach(sub_17DEC, {
        onEnter(args) {
            console.log('enter sub_17DEC')

        },
        onLeave(retval) {
            console.log('leave sub_17DEC')
            var ptr_to_str = Memory.readPointer(retval.add(24)); // result[2]
            console.log('sub_17DEC retval Content =', Memory.readUtf8String(ptr_to_str));
        }
    });
}

function hook_B3A8(baseAddr) {
    const sub_B3A8 = baseAddr.add(0xB3A8);
    Interceptor.attach(sub_B3A8, {
        onEnter(args) {
            this.out = args[0];
            console.log('enter sub_B3A8')
        },
        onLeave(retval) {
            var ptr_to_str = Memory.readPointer(this.out.add(16)); // result[2]
            console.log('sub_B3A8 -> v13 =', ptr_to_str);
            console.log('Content =', Memory.readUtf8String(ptr_to_str));
        }
    });

}

function hook_422E4(baseAddr) {
    const sub_422E4 = baseAddr.add(0x422E4);
    Interceptor.attach(sub_422E4, {
        onEnter(args) {
            console.log('enter sub_422E4')
            this.a3 = args[2];

        },

        onLeave(retval) {
            console.log('retval sub_422E4')
            let out = this.a3;
            const tag = Memory.readU8(out);
            let ptr, len;
            if ((tag & 1) === 0) {
                len = tag >>> 1;
                ptr = out.add(8);
                console.log('sub_422E4 inline')
            } else {
                len = Memory.readU64(out.add(8));
                ptr = Memory.readPointer(out.add(16));
                console.log('sub_422E4 走堆内存')
            }
            try {
                const str = Memory.readUtf8String(ptr);  // 不给 len，Frida 自动遇 0 终止
                console.log("retval sub_422E4 string:", str);
                // const trace = Thread.backtrace(this.context, Backtracer.ACCURATE)
                //     .map(addr => DebugSymbol.fromAddress(addr).toString())
                //     .join("\n");
                // console.log("[Call Stack]\n" + trace)
            } catch (e) {
                console.warn("Invalid UTF-8 at offset", e.offset || "?");
            }
        }
    });
}

function hook_170B4(baseAddr) {
    const sub_170B4 = baseAddr.add(0x170B4);
    Interceptor.attach(sub_170B4, {
        onEnter(args) {
            console.log('enter sub_170B4')
            let a2 = args[1];
            let a2_str = Java.cast(a2, Java.use('java.lang.String'));
            console.log('sub_170B4 a2:', a2_str);
            // const trace = Thread.backtrace(this.context, Backtracer.ACCURATE)
            //     .map(addr => DebugSymbol.fromAddress(addr).toString())
            //     .join("\n");
            // console.log("[Call Stack]\n" + trace)
        },

        onLeave(retval) {
            console.log('retval sub_170B4:', retval.readCString())
        }
    });
}

function hook_14A50(baseAddr) {
    const sub_14A50 = baseAddr.add(0x14A50);
    Interceptor.attach(sub_14A50, {
        onEnter(args) {
            console.log('enter sub_14A50')
        },

        onLeave(retval) {
            console.log('retval sub_14A50:', retval.readCString())
            // const trace = Thread.backtrace(this.context, Backtracer.ACCURATE)
            //     .map(addr => DebugSymbol.fromAddress(addr).toString())
            //     .join("\n");
            // console.log("[Call Stack]\n" + trace)

        }
    });
}

function hook_43190(baseAddr) {
    const sub_43190 = baseAddr.add(0x43190);
    Interceptor.attach(sub_43190, {
        onEnter(args) {
            console.log('enter sub_43190')
            let a2 = args[1];
            let a3 = args[2];
            Java.perform(function () {
                let a2_str = Java.cast(a2, Java.use('java.lang.String'));
                let a3_str = Java.cast(a3, Java.use('java.lang.String'));
                console.log(`[sub_43190] a2${a2_str},a3:${a3_str}`);
            })

        },

        onLeave(retval) {
        }
    });
}

function hook_42838(baseAddr) {
    const sub_42838 = baseAddr.add(0x42838);
    Interceptor.attach(sub_42838, {
        onEnter(args) {
            console.log('enter sub_42838')
            let a2 = args[1].readCString();
            let a3 = args[2].readCString();
            console.log(`[sub_42838] a2-> ${a2},a3-> ${a3}`);
            const trace = Thread.backtrace(this.context, Backtracer.ACCURATE)
                .map(addr => DebugSymbol.fromAddress(addr).toString())
                .join("\n");
            console.log("[Call Stack]\n" + trace)
        },

        onLeave(retval) {
            console.log('retval sub_42838')
        }
    });
}

function hook_tmp(baseAddr) {
    // const sub_AF08 = baseAddr.add(0xAF08);
    // Interceptor.attach(sub_AF08, {
    //     onEnter(args) {
    //         const strPtr = args[1];
    //         try {
    //             const s = strPtr.readUtf8String();
    //             console.log(`[sub_AF08] preparing string: "${s}"`);
    //         } catch (e) {
    //         }
    //     }
    // });
    // const sub_3E5F8 = baseAddr.add(0x3E5F8);
    // Interceptor.attach(sub_3E5F8, {
    //     onEnter(args) {
    //         console.log('enter sub_3E5F8')
    //         let w9 = this.context.x9.toInt32();  // 读取 W9 寄存器的值
    //         console.log('W9 = ' + w9);
    //
    //         if ((w9 & 1) !== 0) {
    //             console.log('W9 : v33 = v255;');
    //         } else {
    //             console.log('W9 :v33 = v155');
    //         }
    //     }
    // });

    // const sub_22E90 = baseAddr.add(0x22E90);
    // Interceptor.attach(sub_22E90, {
    //     onEnter(args) {
    //         console.log('[+] sub_22E90 result enter')
    //         let x8 = this.context.x8;
    //         console.log('x8:\n', x8)
    //     },
    //     onLeave(retval) {
    //         console.log('[+] sub_22E90 result leave')
    //     }
    // })
    // const sub_22E68 = baseAddr.add(0x22E68);
    // Interceptor.attach(sub_22E68, {
    //     onEnter(args) {
    //         console.log('[+] sub_22E68 v42 enter')
    //         let x8 = this.context.x8;
    //         console.log('x8:\n', x8)
    //     },
    //     onLeave(retval) {
    //         console.log('[+] sub_22E68 v42 leave')
    //     }
    // })
    //
    // const sub_22E88 = baseAddr.add(0x22E88);
    // Interceptor.attach(sub_22E88, {
    //     onEnter(args) {
    //         console.log('[+] sub_22E88 v42m2 enter')
    //         let x9 = this.context.x9;
    //         console.log('x9:\n', x9)
    //     },
    //     onLeave(retval) {
    //         console.log('[+] sub_22E88 v42m2 leave')
    //     }
    // })

    // const sub_230DC = baseAddr.add(0x230DC);
    // Interceptor.attach(sub_230DC, {
    //     onEnter(args) {
    //         console.log('[+] sub_230DC v36 enter')
    //         let x0 = this.context.x0;
    //         let x1 = this.context.x1
    //
    //         console.log('v36:\n', x0, x1)
    //     },
    //     onLeave(retval) {
    //         console.log('[+] sub_230DC v36 leave')
    //     }
    // })
}

function hook_main() {
    const baseAddr = Module.findBaseAddress(libName);
    if (!baseAddr) {
        console.error("❌ 未找到模块:", libName);
        return;
    }
    console.log('baseadd', baseAddr)
    // sub_235F4(baseAddr);
    hook_tmp(baseAddr);
    // hook_B3A8(baseAddr);
    // ----------开始----------//
    // 中间比较慢，逆完可以注释
    // hook_1BE30(baseAddr);
    hook_1C514(baseAddr);
    hook_sub_17DEC(baseAddr);
    hook_422E4(baseAddr);
    hook_170B4(baseAddr);
    hook_14A50(baseAddr);
    // hook_43190(baseAddr);
    hook_42838(baseAddr);
    // ----------结束----------//
    hook_43BDC(baseAddr);
    hook_20720(baseAddr);
    hook_1d6f0(baseAddr);
    // hook_sasa20(baseAddr);
    hook_235F4(baseAddr);
    // hook_235F4_bak(baseAddr);
    hook_2349c(baseAddr);
    // sign的输出
    hook_sign(baseAddr);
    // sigi标志位明文做rsa+aes做md5去第5个字节
    hook_md5_encrypt(baseAddr);
    // sign字段其中的第一个标志位
    hook_sign_md5(baseAddr);
    // 根据id取固定值，比如RSA的公钥
    hook_rsa_key_common(baseAddr);
    // aes加密的函数
    hook_aes_encrypt(baseAddr);
    // key的明文，也就是params aes的key,iv生成的地方
    aes_key_iv();
    // params做aes的地方
    hook_params_aes(baseAddr);
    // 最终body生成的结果
    hook_body(baseAddr);
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
