const libName = "libgdtqone.so";

function hook_native() {
    const base = Module.findBaseAddress(libName);
    if (!base) {
        console.log('not found base')
        return
    }
    const sub_3AA20 = base.add(0x3AA20)
    console.log(`sub_3AA20=${sub_3AA20}`)
    Interceptor.attach(sub_3AA20, {
        onEnter(args) {
            console.log('enter sub_3AA20')
            const a3 = args[2].toInt32();
            // int i
            const a4 = args[3].toInt32();
            // int i2
            const a5 = args[4].toInt32();
            // String str
            const a6_ori = args[5];
            const a6 = Java.vm.getEnv().getStringUtfChars(a6_ori, null).readCString();

            // int i3
            const a7 = args[6].toInt32();

            // String[] strArr
            const a8 = args[7];
            let strList = [];
            try {
                const env = Java.vm.getEnv();
                const arrayLen = env.getArrayLength(a8);
                for (let i = 0; i < arrayLen; i++) {
                    const jstrItem = env.getObjectArrayElement(a8, i);
                    const item = env.getStringUtfChars(jstrItem, null).readCString();
                    strList.push(item);
                }
            } catch (e) {
                strList = ["<error reading array>"];
            }

            // String str2
            const a9 = args[8];
            const str2 = Java.vm.getEnv().getStringUtfChars(a9, null).readCString();

            console.log("[*] Called r():");
            console.log("  a3    =", a3);
            console.log("  a4    =", a4);
            console.log("  a5   =", a5);
            console.log("  a6  =", a6);
            console.log("  a7   =", a7);
            console.log("  a8=", strList);
            console.log("  a9 =", str2);


        },
        onLeave(retval) {
            Java.perform(function () {
                const strObj = Java.cast(retval, Java.use('java.lang.String'));
                console.log("  ↳ String content:", strObj.toString());
            })
        }
    })

    const sub_FDA8 = base.add(0xFDA8)
    Interceptor.attach(sub_FDA8, {
        onEnter(args) {
            console.log('call sub_FDA8')
            console.log(args[0].toInt32())
        },
        onLeave(retval) {
        }
    });
    const sub_1700C = base.add(0x1700C)
    Interceptor.attach(sub_1700C, {
        onEnter(args) {
            console.log('call sub_1700C')
        },
        onLeave(retval) {
            console.log('sub_1700C retval', Memory.readPointer(retval).readCString())
        }
    });
}


function hook_system() {
    const libname = libName; // 改成你的

    const waitForLib = () => {
        const m = Process.findModuleByName(libname);
        if (m) {
            console.log("🧬 Found", libname, "at", m.base);
            hook_native();
        } else {
            setTimeout(waitForLib, 100); // 重试
        }
    };

    waitForLib();

}


setImmediate(hook_system);
