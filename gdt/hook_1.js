function showStacks() {
    console.log(
        Java.use("android.util.Log")
            .getStackTraceString(
                Java.use("java.lang.Throwable").$new()
            )
    );
}

function hook_start() {

    // let u0 = Java.use("com.qq.e.comm.plugin.u0");
    // u0["a"].overload('java.lang.String', 'java.lang.String').implementation = function (str, str2) {
    //     console.log(`u0.a is called: str=${str}, str2=${str2}`);
    //     this["a"](str, str2);
    // };

    let pro = Java.use("yaq.pro");
    pro["getobjresult"].implementation = function (i, i2, objArr) {
        let result = this["getobjresult"](i, i2, objArr);
        if (i === 282) {
            console.log(`pro.getobjresult is called: i=${i}, i2=${i2}, objArr=${objArr}`);
            console.log(`pro.getobjresult result=${result}`);
        }

        return result;
    };
}


function hook_classloader() {
    Java.perform(function () {
        Java.enumerateClassLoaders({
            onMatch: function (loader) {
                try {
                    Java.classFactory.loader = loader; // 设置当前 ClassLoader
                    hook_start();

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
