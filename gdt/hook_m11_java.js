function find_classloader() {
    Java.perform(function () {
        console.log("[+] Starting simplified Lichee hook...");


        // Hook DexClassLoader创建
        var DexClassLoader = Java.use("dalvik.system.DexClassLoader");
        DexClassLoader.$init.overload('java.lang.String', 'java.lang.String', 'java.lang.String', 'java.lang.ClassLoader').implementation = function (dexPath, optimizedDirectory, librarySearchPath, parent) {
            console.log("[+] DexClassLoader created with path: " + dexPath);

            var result = this.$init(dexPath, optimizedDirectory, librarySearchPath, parent);
            // 如果是目标DEX文件
            if (dexPath && dexPath.indexOf("gdt_plugin.jar") !== -1) {
                console.log("[!] Target ClassLoader saved!");
                Java.enumerateClassLoaders({
                    onMatch: function (loader) {
                        try {
                            if (loader.findClass("com.tencent.turingfd.sdk.ams.au.Lichee")) {
                                console.log('find class Lichee');
                                Java.classFactory.loader = loader;      //切换classloader
                                hook_java()
                            }

                        } catch (error) {
                            // console.log("222222222222");
                        }
                    }, onComplete: function () {
                    }
                });

            }

            return result;
        };


    });
}

function byteArrayToHexString(byteArray) {
    const HEX_CHARS = '0123456789abcdef';
    let hexString = '';

    for (let i = 0; i < byteArray.length; i++) {
        const code = byteArray[i] & 0xff;
        hexString += HEX_CHARS.charAt(code >> 4) + HEX_CHARS.charAt(code & 0xf);
    }

    return hexString;
}

function printMap(param) {
    let keys = param.keySet();
    let iterator = keys.iterator();
    while (iterator.hasNext()) {
        let k = iterator.next();
        console.log(k + " : " + param.get(k));
    }

}

function hook_java() {
    console.log('enter hook java');
    // var Lichee = Java.use("com.tencent.turingfd.sdk.ams.au.Lichee");
    // Lichee["a"].overload('android.content.Context', 'boolean').implementation = function (context, z) {
    //     console.log(`Lichee.a is called: context=${context}, z=${z}`);
    //     let result = this["a"](context, z);
    //     console.log(byteArrayToHexString(result))
    //     console.log(`Lichee.a result=${result}`);
    //     return result;
    // };

    let TNative$aa = Java.use("com.tencent.turingfd.sdk.ams.au.TNative$aa");
    TNative$aa["e90_BD4FE23C352252DC"].implementation = function (sparseArray, context, map, i) {
        printMap(map);
        console.log(`TNative$aa.e90_BD4FE23C352252DC is called: sparseArray=${sparseArray}, context=${context}, map=${JSON.stringify(map)}, i=${i}`);
        let result = this["e90_BD4FE23C352252DC"](sparseArray, context, map, i);
        console.log(`TNative$aa.e90_BD4FE23C352252DC result=${result}`);
        return result;
    };
}

setImmediate(find_classloader);
