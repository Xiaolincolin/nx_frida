const libName = "libgdtqone.so";

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

                // break
            }
        }
    }
}

function hook_method_find() {


    Java.perform(function () {
        const methodMap = new Map();
        const JNI_GetMethodID = getSymbol('GetMethodID');
        const JNI_CallObjectMethodV = getSymbol('CallObjectMethodV');
        const JNI_CallStaticObjectMethodV = getSymbol('CallStaticObjectMethodV');

        Interceptor.attach(JNI_GetMethodID, {
            onEnter: function (args) {
                this.clazz = args[1];
                this.namePtr = args[2];
                this.sigPtr = args[3];
            },
            onLeave: function (retval) {
                try {
                    const name = Memory.readCString(this.namePtr);
                    const sig = Memory.readCString(this.sigPtr);
                    let clazz = "UnknownClass";
                    try {
                        const JNIEnv = Java.vm.getEnv();
                        const jclassStr = JNIEnv.getClassName(this.clazz);
                        clazz = jclassStr ? jclassStr.toString() : "UnknownClass";
                    } catch (e) {
                        console.error("[!] getClassName failed:", e);
                    }
                    // console.log(`[GetMethodID] ${clazz} → ${name} -> ${sig}`);
                    methodMap.set(retval.toString(), {
                        className: clazz,
                        name: name,
                        signature: sig
                    });
                } catch (e) {
                    console.error("[!] Error reading method info:", e);
                }
            }
        });

        function dumpVaList(env, vaListPtr, sig) {
            try {
                if (!sig || !sig.startsWith('(')) return;
                const argsTypes = sig.match(/\((.*?)\)/)[1].split("");
                const jniEnv = Java.vm.getEnv();

                console.log(" → Args:");
                for (let i = 0; i < argsTypes.length; i++) {
                    const type = argsTypes[i];
                    const argPtr = vaListPtr.add(i * Process.pointerSize);
                    if (type === 'Ljava/lang/String;'.charAt(0)) {
                        const jstr = Memory.readPointer(argPtr);
                        if (!jstr.isNull()) {
                            const jstrObj = jniEnv.getStringUtfChars(jstr, null);
                            console.log("   [" + i + "] = \"" + jstrObj.readUtf8String() + "\"");
                        } else {
                            console.log("   [" + i + "] = null");
                        }
                    } else {
                        const val = Memory.readPointer(argPtr);
                        console.log("   [" + i + "] = " + val);
                    }
                }
            } catch (e) {
                console.error("[!] Failed to parse va_list: ", e);
            }
        }

        function hookCallMethodV(addr, isStatic) {
            Interceptor.attach(addr, {
                onEnter: function (args) {
                    this.methodID = args[2];
                    this.jobjectOrClass = args[1];
                    this.env = args[0];
                    this.vaListPtr = args[3];
                },
                onLeave: function (retval) {
                    try {
                        const key = this.methodID.toString();
                        const info = methodMap.get(key);
                        if (info) {
                            console.log("\n[📦] " + (isStatic ? "CallStaticObjectMethodV" : "CallObjectMethodV"));
                            console.log(" → Class: " + info.className);
                            console.log(" → Method: " + info.name);
                            console.log(" → Signature: " + info.signature);
                            // if (info.className.indexOf("com.qq") >= 0) {
                            //     console.log(" → 自有类")
                            //     dumpVaList(this.env, this.vaListPtr, info.signature);
                            // }
                            console.log(" → Return: " + retval);
                        } else {
                            console.log("\n[⚠️] Unknown methodID:", key);
                        }
                    } catch (e) {
                        console.error("[!] Failed to process method call:", e);
                    }
                }
            });
        }

        hookCallMethodV(JNI_CallObjectMethodV, false);
        hookCallMethodV(JNI_CallStaticObjectMethodV, true);
    });

}

function hook_system() {
    const libname = libName; // 改成你的

    const waitForLib = () => {
        const m = Process.findModuleByName(libname);
        if (m) {
            console.log("🧬 Found", libname, "at", m.base);
            hook_method_find();
        } else {
            setTimeout(waitForLib, 100); // 重试
        }
    };

    waitForLib();

}


setImmediate(hook_system);
