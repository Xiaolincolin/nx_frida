function hook_mu_p_t2() {
    Java.perform(() => {

        let pro = Java.use("yaq.pro");
        pro["getobjresult"].implementation = function (i, i2, objArr) {
            let result = this["getobjresult"](i, i2, objArr);
            if (i === 305) {
                console.log(`pro.getobjresult is called: i=${i}, i2=${i2}, objArr=${objArr}`);
                console.log(`pro.getobjresult result=${JSON.stringify(result)}`);
            }

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
                    hook_mu_p_t2();

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
