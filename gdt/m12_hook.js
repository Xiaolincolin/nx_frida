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
    Interceptor.attach(sub_235F4, {
        onEnter(args) {
            this.a1 = args[0];
            let a2 = args[1];
            let a3 = args[2];
            let a4 = args[3];
            console.log('enter sub_235F4');
            console.log('[+] a1->', hexdump(this.a1, {length: 32}));
            console.log('[+] a2->', hexdump(a2, {length: 32}));
            console.log('[+] a3->', a3.toString(16));
            console.log('[+] a4->', a4.toInt32());
        },
        onLeave(retval) {
            const ks = Memory.readByteArray(this.a1, 64);
            console.log('[*] Keystream Block (sub_235F4):');
            console.log(hexdump(ks, {offset: 0, length: 64}));
            console.log('[+] sub_235F4 leave ');

            const ks1 = Memory.readByteArray(retval, 64);
            console.log('[*] Keystream Block (sub_235F4) retval:');
            console.log(hexdump(ks, {offset: 0, length: 64}));
            console.log('[+] sub_235F4 leave retval');
        }

    })
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
            // this.a5 = args[4]; // a5
            this.a5 = this.context.x8;
            console.log('====', args[4])

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
            } else {
                len = tag >> 1;
                data_str = a4.add(8);

            }
            const keyBytes = Memory.readByteArray(data_str, len);
            const keyHex = Array.from(new Uint8Array(keyBytes)).map(b => `0x${b.toString(16).padStart(2, '0')}`);

            console.log(`[+] sub_2349C a4(${len}) bytes:`, hexdump(data_str, {length: len}));
            console.log("plaintext[] = {\n  " + keyHex.join(', ').replace(/(.{60})/g, '$1\n  ') + "\n}");
        },
        onLeave(retval) {
            console.log('[+] sub_2349C leave:');
            console.log(hexdump(this.a5, {length: 32}))
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
}

function hook_tmp(baseAddr) {
    // const sub_22C24 = baseAddr.add(0x22C24);
    // Interceptor.attach(sub_22C24, {
    //     onEnter(args) {
    //         console.log('[*] Entered sub_22C20');
    //         const val = this.context.x8;
    //         console.log('[*] Loaded byte from [X29 - 0x8A] =', val);
    //     }
    // });

    // const sub_22BB8 = baseAddr.add(0x22BB8);
    // Interceptor.attach(sub_22BB8, {
    //     onEnter(args) {
    //         console.log('[*] Entered sub_22BB8');
    //         try {
    //             const val = this.context.x29.sub(0x90).readU8();
    //             console.log('[*] Read byte from [SP + 0x90]:', val);
    //         } catch (e) {
    //             console.warn('[!] Failed to read:', e);
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
    // sub_235F4(baseAddr);
    hook_tmp(baseAddr);
    hook_235F4(baseAddr);
    hook_235F4_bak(baseAddr);
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
