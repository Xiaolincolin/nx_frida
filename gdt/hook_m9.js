function hook_m9() {
    let v1 = Java.use("com.qq.e.comm.plugin.v1");
    v1["b"].overload().implementation = function () {
        console.log(`v1.b is called`);
        let result = this["b"]();
        console.log(`v1.b result=${result}`);
        return result;
    };
}

function hook_classloader() {
    Java.perform(function () {
        Java.enumerateClassLoaders({
            onMatch: function (loader) {
                try {
                    Java.classFactory.loader = loader; // 设置当前 ClassLoader
                    hook_m9();

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

function find_x5_target_addr() {
    const base = Module.findBaseAddress("libyaqbasic.3e364a2a.so");
    if (!base) {
        console.log('not found base')
        return
    }
    const sub_AA0 = base.add(0xAA0)
    console.log(`sub_AA0=${sub_AA0}`)
    Interceptor.attach(sub_AA0, {
        onEnter(args) {
            console.log(`🚀 enter sub_AA0`)
            let x5 = this.context.x5;
            console.log(`🚀 enter sub_AA0 x5=${x5}`)
            var find_module = Process.findModuleByAddress(x5);
            console.log(`🚀 enter sub_AA0 find_module=${find_module}`)
            console.log(" fnOffset:", ptr(x5).sub(find_module.base), " callee:", DebugSymbol.fromAddress(this.returnAddress));
        }
    })
}

function hook_native() {
    const base = Module.findBaseAddress("libyaqpro.3e364a2a.so");
    if (!base) {
        console.log('not found base')
        return
    }
    let is_hook = false
    const sub_b484 = base.add(0xb484)
    console.log(`sub_b484=${sub_b484}`)
    Interceptor.attach(sub_b484, {
        onEnter(args) {
            this.code_id = args[2].toInt32();
            if (this.code_id === 282) {
                is_hook = true
                console.log(`🚀 sub_b484 调用`)
            }
        },
        onLeave(retval) {
            if (this.code_id === 282) {
                is_hook = false
            }
        }
    })

    const sub_A0A0 = base.add(0x5fdf4)
    Interceptor.attach(sub_A0A0, {
        onEnter(args) {
            if (is_hook) {
                console.log(`🚀 sub_A0A0 调用`)
            }
        },
        onLeave(retval) {
        }
    })

}

setImmediate(hook_native);
