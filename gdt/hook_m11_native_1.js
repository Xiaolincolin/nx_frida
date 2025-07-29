function hook_1F5B4(baseAddr) {
    const addr_sub_1F5B4 = baseAddr.add(0x1F5B4);
    Interceptor.attach(addr_sub_1F5B4, {
        onEnter: function (args) {
            this.inputPtr = args[0];
            this.inputLen = args[1].toInt32();
            this.outBufPtr = args[2];
            this.outLenPtr = args[3];

            if (this.inputLen < 0x8000) {
                const raw = Memory.readByteArray(this.inputPtr, this.inputLen);
                console.log("\n== sub_1F5B4 INPUT == length:", this.inputLen);
                console.log(hexdump(raw));
            }
        },

        onLeave: function (retval) {
            const outPtr = Memory.readPointer(this.outBufPtr);
            const outLen = Memory.readU32(this.outLenPtr);
            console.log("== sub_1F5B4 OUTPUT (ptr) ==");
            console.log("ptr:", outPtr, "len:", outLen);

            if (!outPtr.isNull() && outLen > 0 && outLen < 0x10000) {
                const encrypted = Memory.readByteArray(outPtr, outLen);
                console.log(hexdump(encrypted));
            }
        }
    });

}


function hook_27BA8(baseAddr) {
    let sub_27BA8 = baseAddr.add(0x27BA8);
    Interceptor.attach(sub_27BA8, {
        onEnter: function (args) {
            this.ptrOut = args[1];  // void **ptr
            this.lenOut = args[2];  // int *len
            const ptrBuf = Memory.readPointer(this.ptrOut);
            const len = Memory.readU32(this.lenOut);

            console.log("enter [sub_27BA8] ptr =", ptrBuf, "len =", len);
            if (!ptrBuf.isNull() && len > 0 && len < 4096) {
                const data = Memory.readByteArray(ptrBuf, len);
                console.log("sub_27BA8 intput:");
                console.log(hexdump(data));
            } else {
                console.log("sub_27BA8 intput is null");
            }
        },
        onLeave: function (retval) {
            const ptrBuf = Memory.readPointer(this.ptrOut);
            const len = Memory.readU32(this.lenOut);

            console.log("[sub_27BA8] ptr =", ptrBuf, "len =", len);
            if (!ptrBuf.isNull() && len > 0 && len < 4096) {
                const data = Memory.readByteArray(ptrBuf, len);
                console.log("sub_27BA8 output:");
                console.log(hexdump(data));
            }
        }
    });

}

function hook_1D05C(baseAddr) {
    const sub_1D05C = baseAddr.add(0x1D05C);
    Interceptor.attach(sub_1D05C, {
        onEnter: function (args) {
            this.a1 = args[0];  // 结构体原始地址
            this.a2 = args[1];  // out_ptr
            this.a3 = args[2];  // out_len
        },
        onLeave: function (retval) {
            if (retval.toInt32() !== 0) return;  // 错误跳过

            let output_ptr = Memory.readPointer(this.a2);
            let output_len = Memory.readU32(this.a3);
            console.log("=== sub_1D05C called ===");
            console.log("output ptr:", output_ptr, "len:", output_len);
            let output_bytes = Memory.readByteArray(output_ptr, output_len);
            console.log(hexdump(output_bytes, {length: output_len}));
        }
    });

}

function hook_27A04(baseAddr) {
    const sub_27A04 = baseAddr.add(0x27A04);
    Interceptor.attach(sub_27A04, {
        onEnter(args) {
            this.inBuf = args[0];
            this.inLen = args[1].toInt32();
            this.outBufPtr = args[2];
            this.outLenPtr = args[3];

            console.log("[sub_27A04] called");
            if (this.inLen > 0 && this.inLen < 0x8000) {
                const data = Memory.readByteArray(this.inBuf, this.inLen);
                console.log("(before):");
                console.log(hexdump(data));
            }
        },
        onLeave(retval) {
            const outBuf = Memory.readPointer(this.outBufPtr);
            const outLen = Memory.readU32(this.outLenPtr);
            if (!outBuf.isNull() && outLen > 0 && outLen < 0x8000) {
                const result = Memory.readByteArray(outBuf, outLen);
                console.log("(after):");
                console.log(hexdump(result));
            }
        }
    });
}

function hook_2E668(baseAddr) {
    const sub_2E668 = baseAddr.add(0x2E668);
    Interceptor.attach(sub_2E668, {
        onEnter(args) {
            this.inBuf = args[0];
            this.inLen = args[1].toInt32();
            this.outBufPtr = args[2];
            this.outLenPtr = args[3];
            this.level = args[4].toInt32();

            console.log("[sub_2E668] zlib compress called");
            if (this.inLen > 0 && this.inLen < 0x8000) {
                const data = Memory.readByteArray(this.inBuf, this.inLen);
                console.log("Original (before zlib):");
                console.log(hexdump(data));
            }
        },
        onLeave(retval) {
            const outBuf = Memory.readPointer(this.outBufPtr);
            const outLen = Memory.readU32(this.outLenPtr);
            if (!outBuf.isNull() && outLen > 0 && outLen < 0x8000) {
                const result = Memory.readByteArray(outBuf, outLen);
                console.log("Compressed (zlib deflate):");
                console.log(hexdump(result));
            }
        }
    });
}

function hook_2F3E0(baseAddr) {
    const subPtr = baseAddr.add(0x2F3E0);
    Interceptor.attach(subPtr, {
        onEnter: function (args) {
            const a1 = args[0]; // const jbyte*
            const a2 = args[1].toInt32(); // length
            const a3 = args[2]; // result pointer

            console.log(">> sub_2F3E0 called");
            console.log("Length:", a2);
            console.log("Result ptr (a3):", a3);

            if (a2 > 0 && a2 < 4096 && !a1.isNull()) {
                // 打印原始十六进制数据
                const rawBytes = Memory.readByteArray(a1, a2);
                console.log("Raw bytes:");
                console.log(hexdump(rawBytes, {
                    length: a2,
                }));

            }
        }
    });
}

function hook_tvl(baseAddr) {
    const sub_1C118 = baseAddr.add(0x1C118);
    Interceptor.attach(sub_1C118, {
        onEnter: function (args) {
        },
        onLeave: function (retval) {
            console.log("sub_1C118 return:", hexdump(retval.readPointer(), {length: 0x18}));
        }
    });
}

function hook_main(libname) {
    const baseAddr = Module.findBaseAddress(libname);
    if (!baseAddr) {
        console.error("❌ 未找到模块:", libname);
        return;
    }
    console.log('baseAddr:', baseAddr);
    // hook_tvl(baseAddr);
    hook_1D05C(baseAddr);
    hook_27A04(baseAddr);
    hook_2E668(baseAddr);
    hook_1F5B4(baseAddr);
    hook_27BA8(baseAddr);
    hook_2F3E0(baseAddr);
}

function hook_system() {
    const libname = "libturingau.3e364a2a.so";

    const waitForLib = () => {
        const m = Process.findModuleByName(libname);
        if (m) {
            console.log("🧬 Found", libname, "at", m.base);
            hook_main(libname);
        } else {
            setTimeout(waitForLib, 50); // 重试
        }
    };

    waitForLib();

}


setImmediate(hook_system);

