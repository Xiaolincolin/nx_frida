const libName = "libgdtqone.so";


function hook_tmp(baseAddr) {
    const target = baseAddr.add(0xA8F8);
    Interceptor.attach(target, {
        onEnter(args) {
            // this.a1 = args[2];   // 原始明文结构体
            this.a1 = this.context.x8;
            const flag = this.a1.readU8();
            let len, dataPtr;
            if ((flag & 1) === 0) {
                len = flag >> 1;
                dataPtr = this.a1.add(8);
            } else {
                len = this.a1.add(8).readU32();
                dataPtr = this.a1.add(16).readPointer();
            }
            const original = Memory.readByteArray(dataPtr, len);
            console.log(`[target] enter Plaintext (${len} bytes): \n${hexdump(original, {length: len})}`);
        },

        onLeave(retval) {
            const flag = this.a1.readU8();
            let len, dataPtr;
            if ((flag & 1) === 0) {
                len = flag >> 1;
                dataPtr = this.a1.add(8);
            } else {
                len = this.a1.add(8).readU32();
                dataPtr = this.a1.add(16).readPointer();
            }
            const original = Memory.readByteArray(dataPtr, len);
            console.log(`[target] retval Plaintext (${len} bytes): \n${hexdump(original, {length: len})}`);
        }
    });
}

function hook_1F0E0(baseAddr) {
    const sub_1F0E0_ptr = baseAddr.add(0x1F0E0);
    Interceptor.attach(sub_1F0E0_ptr, {
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
            const original = Memory.readByteArray(dataPtr, len);
            console.log(`[sub_1F0E0] enter Plaintext (${len} bytes): \n${hexdump(original, {length: len})}`);
            // const backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE)
            //     .map(addr => DebugSymbol.fromAddress(addr).toString())
            //     .join("\n");
            //
            // console.log("[Call Stack]\n" + backtrace);
        },

        onLeave(retval) {

        }
    });
}


function hook_1812C(baseAddr) {
    const sub_1812C = baseAddr.add(0x1812C);
    Interceptor.attach(sub_1812C, {
        onEnter(args) {
            this.a1 = args[1];   // 原始明文结构体
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
            const skipBytes = [0x00, 0x2f, 0x5b];

            if (skipBytes.includes(firstByte)) {
                return;
            }
            const original = Memory.readByteArray(dataPtr, len);
            console.log(`[sub_1812C] enter (${len} bytes)\n`, original)


        },

        onLeave(retval) {

        }
    });
}

function hook_17F2C(baseAddr) {
    // todo 追踪每个值的来源
    const sub_17F2C = baseAddr.add(0x17F2C);
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


function hook_main() {
    const baseAddr = Module.findBaseAddress(libName);
    if (!baseAddr) {
        console.error("❌ 未找到模块:", libName);
        return;
    }
    console.log('baseadd', baseAddr);
    hook_tmp(baseAddr);
    hook_1F0E0(baseAddr);
    // hook_1812C(baseAddr);
    // hook_17F2C(baseAddr);
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
