function showStacks() {
    console.log(
        Java.use("android.util.Log")
            .getStackTraceString(
                Java.use("java.lang.Throwable").$new()
            )
    );
}

function hook_req() {
    Java.perform(function () {

        let v1 = Java.use("com.qq.e.comm.plugin.v1");
        v1["b"].overload('com.qq.e.comm.plugin.q1', 'com.qq.e.comm.plugin.sv', 'com.qq.e.comm.plugin.u1').implementation = function (a1, a2, a3) {
            showStacks()
            console.log(`v1.b is called: null=${a1}, null=${a2}, null=${a3}`);
            let result = this["b"](a1, a2, a3);
            console.log(`v1.b result=${result}`);
            return result;
        };

    })
}

function hook_classloader() {
    Java.perform(function () {
        Java.enumerateClassLoaders({
            onMatch: function (loader) {
                try {
                    Java.classFactory.loader = loader; // 设置当前 ClassLoader
                    hook_req();

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
