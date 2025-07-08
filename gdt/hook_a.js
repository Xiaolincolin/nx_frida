function hook_classloader() {
    Java.perform(function () {
        Java.enumerateClassLoaders({
            onMatch: function (loader) {
                try {
                    Java.classFactory.loader = loader; // 设置当前 ClassLoader
                    let ia_class = Java.use("com.qq.e.comm.plugin.ia");
                    let t2_class = Java.use("com.qq.e.comm.plugin.t2");

                    if (!ia_class || !t2_class) {
                        console.log('t2_class not found');
                        return
                    }
                    console.log('find class')
                    let ia = Java.use("com.qq.e.comm.plugin.ia");
                    ia["a"].implementation = function () {
                        console.log(`ia.a is called`);
                        // let p_list = this.b._p;
                        // for (let i = 0; i < p_list.length; i++) {
                        //     let p = p_list[i];
                        //     console.log(`ia.a p[${i}] = ${p}`);
                        // }
                        console.log('this.H->', JSON.stringify(this.a().H.value));
                        let result = this["a"]();
                        console.log(`ia.a result=`, JSON.stringify(result));
                        return result;
                    };

                    // let pro = Java.use("yaq.pro");
                    // pro["getobjresult"].implementation = function (i, i2, objArr) {
                    //     let result = this["getobjresult"](i, i2, objArr);
                    //     if (i == 305) {
                    //         console.log(`pro.getobjresult is called: i=${i}, i2=${i2}, objArr=${objArr}, result=${result}`);
                    //     }
                    //     return result;
                    // };
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

function dump_hex(addr) {
    const base = Module.findBaseAddress('libyaqpro.3e364a2a.so');
    console.log(hexdump(base.add(addr)))
}

function hook_native() {
    const base = Module.findBaseAddress('libyaqpro.3e364a2a.so');
    Interceptor.attach(base.add(0xAA44), {
        onEnter: function (args) {
            console.log(hexdump(base.add(0x79210)))
            console.log("addr_AA44:", this.context.x8);
        },
        onLeave: function (retval) {

        }
    })
}

function main() {
    hook_classloader();
    // hook_native();
}

setImmediate(main);
