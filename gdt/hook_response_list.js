function showStacks() {
    console.log(
        Java.use("android.util.Log")
            .getStackTraceString(
                Java.use("java.lang.Throwable").$new()
            )
    );
}

function hook_start() {
    let pro = Java.use("yaq.pro");
    pro["getVresult"].implementation = function (i, i2, objArr) {
        console.log(`pro.getVresult is called: i=${i}, i2=${i2}, objArr=${objArr}`);
        this["getVresult"](i, i2, objArr);
        console.log("getVresult 调用结束", JSON.stringify(objArr));
    };
}

function hook_getVresult() {
    const moduleName = "libyaqpro.6b3ac992.so";  // 你的so名字改这里
    const baseAddr = Module.findBaseAddress(moduleName);
    if (!baseAddr) {
        console.error("[!] 找不到模块:", moduleName);
        return;
    }
    console.log("[*]", moduleName, "基址:", baseAddr);

    const off_addr = baseAddr.add(0xb570);
    console.log("[*] sub_b570 绝对地址:", off_addr);

    Interceptor.attach(off_addr, {
        onEnter(args) {
            let code_id = args[2].toInt32();
            this.code_id = code_id;
            console.log("[*] 第1个参数:", code_id);
            // if (code_id === 255) {
            //     // 前两个参数通常是jniEnv和jobject/jclass，跳过它们
            //     console.log("    第1个参数:", code_id);
            //     console.log("    第2个参数:", args[3].toInt32());
            //     console.log("    objArr:", args[4]);
            // }
        },
        onLeave(retval) {
            if (this.code_id === 215) {
                console.log("[*] getobjresult 返回值:", retval);
            }
        }
    });
}


function hook_classloader() {
    Java.perform(function () {
        Java.enumerateClassLoaders({
            onMatch: function (loader) {
                try {
                    Java.classFactory.loader = loader; // 设置当前 ClassLoader
                    hook_start();
                    hook_getVresult();

                } catch (error) {
                    if (error.message.includes("ClassNotFoundException")) {
                        // 忽略 ClassNotFound 异常，继续尝试下一个 ClassLoader
                    } else {
                        console.error(`[Error] Loader ${loader}: ${error}`);
                    }
                }
            },
            onComplete: function () {
                console.log("[Info] ClassLoader enumeration complete.");
            }
        });
    });
}


setImmediate(hook_classloader);
