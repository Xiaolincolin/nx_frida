function getSymbol(name) {
    let symbols = Process.getModuleByName("libart.so").enumerateSymbols();
    let addr_target = null;
    for (let index = 0; index < symbols.length; index++) {
        const symbols_one = symbols[index];
        if (symbols_one.name.indexOf("art") >= 0) {
            if (
                symbols_one.name.indexOf("CheckJNI") === -1 &&
                symbols_one.name.indexOf("Notify") === -1 &&
                symbols_one.name.indexOf("mirror") === -1 &&
                symbols_one.name.indexOf("verifier") === -1 &&
                symbols_one.name.indexOf("DexFile") === -1 &&
                symbols_one.name.indexOf("JNIILb1") === -1
            ) {
                if (
                    symbols_one.name.indexOf(name) >= 0
                ) {
                    console.log("target  symbols", JSON.stringify(symbols_one));
                    addr_target = symbols_one.address;
                    console.log("target address = " + addr_target);
                    return addr_target
                }
            }
        }
    }
}

function hook_b570(baseAddr) {
    const sub_b570 = baseAddr.add(0xb570);
    Interceptor.attach(sub_b570, {
        onEnter(args) {

            let a3 = args[2].toInt32();
            this.a3 = a3;
            let a4 = args[3].toInt32();
            let a5 = args[5];
            if (a3 === 255) {
                console.log("[*] sub_b570 调用");
                console.log("    第1个参数:", a3);
                console.log("    第2个参数:", a4);
                console.log("    第3个参数:\n", hexdump(a5));
            }
        },
        onLeave(retval) {
            if (this.a3 === 255) {
                console.log("[*] sub_b570 返回");
            }
        }
    });
}

function hook_sub_B570(baseAddr) {
    const addr = baseAddr.add(0xB570); // 替换为你的实际偏移
    Interceptor.attach(addr, {
        onEnter(args) {
            const env = args[0];        // JNIEnv*
            const objArr = args[4];     // jobjectArray
            let a3 = args[2].toInt32();
            if (a3 === 255) {
                const jniEnv = Java.vm.getEnv();
                Java.perform(() => {
                    const array = objArr;
                    const count = jniEnv.getArrayLength(array);

                    console.log(`[+] getVresult called: array.length = ${count}`);
                    for (let i = 0; i < count; i++) {
                        const element = jniEnv.getObjectArrayElement(array, i);
                        const jstr = Java.cast(element, Java.use("java.lang.Object")).toString();
                        console.log(`    [objArr[${i}]] = ${jstr}`);
                    }
                });
            }

        }
    });
}


function hook_AADC(baseAddr) {
    const sub_AADC = baseAddr.add(0xAADC);
    Interceptor.attach(sub_AADC, {
        onEnter(args) {
            this.a4 = args[3].readCString();
            this.a5 = args[4].toInt32();
            this.a9 = args[8];
            if (this.a4 === 'L' && this.a5 === 1) {
                console.log("[*] sub_AADC 调用");
                console.log("    第4个参数:", this.a4);
                console.log("    第5个参数:", this.a5);
            }
        },
        onLeave(retval) {
            if (this.a4 === 'L' && this.a5 === 1) {
                let a9 = this.a9.add(160).readPointer().add(8).readPointer();
                console.log("    第9个参数:", a9);
                if (!a9.isNull()) {
                    Java.perform(() => {
                        const jstr = Java.cast(a9, Java.use("java.lang.Object")).toString();
                        console.log(`[objArr] = ${jstr}`);
                    });
                }
            }

        }
    });
}

function hook_1A87C(baseAddr) {
    const sub_1A87C = baseAddr.add(0x1A87C);
    const jumpTable = baseAddr.add(0x666B0); // 替换成你 off_666B0 的地址

    Interceptor.attach(sub_1A87C, {
        onEnter(args) {
            const a2 = args[1];
            console.log('[sub_1A87C] v16 address =', a2);
            const type_ptr = Memory.readPointer(a2.add(8));
            const type_val = Memory.readU16(type_ptr);
            const index = type_val & 0xFF;
            console.log(`Jump type: 0x${type_val.toString(16)} → index ${index}`);
            // 跳转表中取出对应函数地址
            const entryAddr = jumpTable.add(index * 8);
            const targetFunc = Memory.readPointer(entryAddr);

            console.log(`[sub_1A87C] jump table entry = ${entryAddr}`);
            console.log(`[sub_1A87C] jump target addr = ${targetFunc}`);
            console.log(`[sub_1A87C] jump target offset = ${targetFunc.sub(baseAddr)}`);

            let a2_ptr = a2.add(160).readPointer().add(8).readPointer();
            let a2_str = a2_ptr.toString(16);
            console.log("    第2个参数:", a2_ptr);
            console.log("    第2个参数:", a2_str);

            if (!a2_ptr.isNull()) {
                Java.perform(() => {
                    const jstr = Java.cast(a2_ptr, Java.use("java.lang.Object")).toString();
                    console.log(`[objArr] = ${jstr}`);
                });
            }
        }
    });

}


function hook_str() {
    let jstr = getSymbol('GetStringUTFChars');
    let cstr = getSymbol('NewStringUTF');
    Interceptor.attach(jstr, {
        onEnter(args) {
            this.jstr = args[1];
            this.env = args[0];
        },
        onLeave(retval) {
            const cstr = Memory.readUtf8String(retval);
            console.log('[GetStringUTFChars] Java String → C String:', cstr);
        }
    });

    Interceptor.attach(cstr, {
        onEnter(args) {
            this.env = args[0];
            this.cstr = Memory.readUtf8String(args[1]);
            console.log('[NewStringUTF] C String → Java String:', this.cstr);
        }
    });

}

function hook_tmp(baseAddr) {
    Java.perform(() => {
        const class_name = baseAddr.add(0x480E0);
        Interceptor.attach(class_name, {
            onEnter(args) {
                let x0 = this.context.x0;
                // console.log(`class_name: ${x0.readCString()}`);
                try {
                    const StrObject = Java.use('java/lang/String');
                    const jsObj = Java.cast(x0, StrObject);
                    console.log("  => return Jstgring:", jsObj.toString());
                } catch (e) {

                }

            },
            onLeave(retval) {
            }
        });
    })
}

function hook_47B88(baseAddr) {
    const class_name = baseAddr.add(0x47BAC);
    Interceptor.attach(class_name, {
        onEnter(args) {
            console.log('enter class_name')
            let x28 = this.context.x28;
            console.log(`class_name: ${x28}`);
            try {
                const Cipher = Java.use('javax.crypto.Cipher');
                const cipher = Java.cast(x28, Cipher);
                console.log('class_name:', 'Cipher')
                // const trace = Thread.backtrace(this.context, Backtracer.ACCURATE)
                //     .map(addr => DebugSymbol.fromAddress(addr).toString())
                //     .join("\n");
                // console.log("[Call Stack]\n" + trace)
            } catch (e) {

            }

        },
        onLeave(retval) {
        }
    });

    const method_ptr = baseAddr.add(0x48008);
    Interceptor.attach(method_ptr, {
        onEnter(args) {
            console.log('enter method_ptr')
            let x2 = this.context.x2;
            let x3 = this.context.x3;
            console.log(`method_ptr: ${x2.readCString()}`);
            console.log(`method_sig: ${x3.readCString()}`);
        },
        onLeave(retval) {
        }
    });

}


function hook_52060(baseAddr) {
    const sub_52060 = baseAddr.add(0x51B54);
    Interceptor.attach(sub_52060, {
        onEnter(args) {
            console.log('enter sub_52060');
            let a5 = args[4];
            console.log(hexdump(a5))

        },
        onLeave(retval) {
        }
    });
}

function hook_main() {
    const moduleName = "libyaqpro.6b3ac992.so";  // 你的so名字改这里
    const baseAddr = Module.findBaseAddress(moduleName);
    if (!baseAddr) {
        console.error("[!] 找不到模块:", moduleName);
        return;
    }
    console.log("[*]", moduleName, "基址:", baseAddr);
    // hook_b570(baseAddr);
    // hook_AADC(baseAddr);
    // hook_1A87C(baseAddr);
    // hook_str();
    // hook_sub_B570(baseAddr);
    // hook_tmp(baseAddr);
    // hook_47B88(baseAddr);
    hook_52060(baseAddr);
}

setImmediate(hook_main);
