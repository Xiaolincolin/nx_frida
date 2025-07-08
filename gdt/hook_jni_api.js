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

function find_filed() {
    // jfieldID → 字段映射
    const jfieldMap = {};  // jfieldID => { class: "com/example/Foo", name: "field", sig: "Ljava/lang/String;" }
    const classMap = {};   // jclass => class name


// === 1. Hook FindClass to record class pointer → class name ===
    const FindClass = getSymbol("FindClass");
    if (FindClass) {
        Interceptor.attach(FindClass, {
            onEnter(args) {
                this.className = Memory.readCString(args[1]);
            },
            onLeave(retval) {
                const ptrStr = retval.toString();
                classMap[ptrStr] = this.className;
                // console.log(`[FindClass] ${this.className} → ${ptrStr}`);
            }
        });
    }

// === 2. Hook GetFieldID / GetStaticFieldID ===
    function hookGetFieldID(symbolName, isStatic = false) {
        const addr = getSymbol(symbolName);
        if (!addr) return;
        Interceptor.attach(addr, {
            onEnter(args) {
                this.clazz = args[1];
                this.name = Memory.readCString(args[2]);
                this.sig = Memory.readCString(args[3]);
            },
            onLeave(retval) {
                const fid = retval.toString();
                const clazzStr = this.clazz.toString();
                const clsName = classMap[clazzStr] || `[${clazzStr}]`;

                jfieldMap[fid] = {
                    class: clsName,
                    name: this.name,
                    sig: this.sig,
                    static: isStatic
                };

                console.log(`[Get${isStatic ? "Static" : ""}FieldID] ${clsName}.${this.name} : ${this.sig} → ${fid}`);
            }
        });
    }

    hookGetFieldID("GetFieldID", false);
    hookGetFieldID("GetStaticField", true);

// === 3. Hook SetObjectField / SetStaticObjectField ===
    function hookSetField(symbolName, isStatic = false) {
        const addr = getSymbol(symbolName);
        if (!addr) return;

        Interceptor.attach(addr, {
            onEnter(args) {
                // 打印调用栈
                const jfieldID = args[2].toString();
                const info = jfieldMap[jfieldID];
                console.log(`\n[SetObjectField]`);
                console.log("  ↳ Target obj:", args[1]);
                console.log("  ↳ jfieldID  :", jfieldID);
                if (info) {
                    console.log(`  ↳ Class     : ${info.class}`);
                    console.log(`  ↳ Field     : ${info.name}`);
                    console.log(`  ↳ Sig       : ${info.sig}`);
                } else {
                    console.log("  ↳ Field info: (unknown)");
                }
                console.log("  ↳ Value     :", args[3]);

                // 如果是字符串，尝试打印字符串内容
                if (info && info.sig === "Ljava/lang/String;") {
                    Java.perform(() => {
                        try {
                            const strObj = Java.cast(ptr(args[3]), Java.use('java.lang.String'));
                            console.log("  ↳ String content:", strObj.toString());
                        } catch (e) {
                            console.log("  ↳ Failed to convert to String:", e.message);
                        }
                    });
                }
                const backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE)
                    .map(addr => DebugSymbol.fromAddress(addr).toString())
                    .join("\n");

                console.log("[Call Stack]\n" + backtrace);
            }
        });

    }

    hookSetField("SetObjectField", false);
    hookSetField("SetStaticObjectField", true);


}

function hook_system() {
    const libname = "libart.so"; // 改成你的

    const waitForLib = () => {
        const m = Process.findModuleByName(libname);
        if (m) {
            console.log("🧬 Found", libname, "at", m.base);
            find_filed();
        } else {
            setTimeout(waitForLib, 100); // 重试
        }
    };

    waitForLib();

}


setImmediate(hook_system);
