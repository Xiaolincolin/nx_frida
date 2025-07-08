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

function main() {
    const baseAddr = Module.findBaseAddress(libName);
    if (!baseAddr) {
        console.error("❌ 未找到模块:", libName);
        return;
    }
    const sub_43BDC = baseAddr.add(0x43BDC);
    const sub_476A0 = baseAddr.add(0x476A0);
    Interceptor.attach(sub_43BDC, {
        onEnter(args) {
            this.tid = Process.getCurrentThreadId();
            let a1 = args[0].toInt32();
            let a2 = args[1].toInt32();
            let a3 = args[2].toInt32();
            let a4 = args[3].toInt32();
            let a5 = args[4].toInt32();
            this.a6 = args[5];
            this.ptrBuf = args[6];
            console.log('enter sub_43BDC');
            console.log(`a1:${a1},a2:${a2},a3:${a3},a4:${a4},a5:${a5}`)
            this.is_stalk = false;
            if (a4 === 8) {
                this.is_stalk = true;
                Stalker.follow(this.tid, {
                    transform: (iterator) => {
                        let instruction = iterator.next();
                        const startAddress = instruction.address;
                        const inRange = startAddress.compare(sub_43BDC) >= 0 &&
                            startAddress.compare(sub_476A0) < 0;
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
        },
        onLeave(retval) {
            if (this.is_stalk) {
                Stalker.unfollow(this.tid);
                Stalker.garbageCollect();
            }
        }
    });
}


function hook_system() {
    const libname = libName; // 改成你的

    const waitForLib = () => {
        const m = Process.findModuleByName(libname);
        if (m) {
            console.log("🧬 Found", libname, "at", m.base);
            main();
        } else {
            setTimeout(waitForLib, 100); // 重试
        }
    };

    waitForLib();

}


setImmediate(hook_system);
