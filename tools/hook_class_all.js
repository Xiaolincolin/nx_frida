/*
    1.获取类下面所有方法
    2.遍历所有方法
    3.获取每个方法的所有重载
    4.遍历重载
    5.implementation hook
*/
function printstack() {
    var Log = Java.use("android.util.Log");
    var Exception = Java.use("java.lang.Exception");
    console.log(Log.getStackTraceString(Exception.$new()));
}

function hookClass(className) {
    var myClass = Java.use(className);
    var methods = myClass.class.getDeclaredMethods();


    methods.forEach(function (method) {
        var methodName = method.getName();
        var overloads = myClass[methodName]?.overloads;

        if (!overloads) return;

        overloads.forEach(function (overload) {
            // 构造方法签名字符串
            var prot = '(';
            for (var i = 0; i < overload.argumentTypes.length; i++) {
                prot += overload.argumentTypes[i].className + ',';
            }
            prot = prot.replace(/,$/, '') + ')';

            var myMethodName = className + '.' + methodName + prot;

            overload.implementation = function () {
                printstack();
                console.log('[+] Call: ' + myMethodName);
                for (var i = 0; i < arguments.length; i++) {
                    try {
                        console.log('    arg[' + i + ']: ' + JSON.stringify(arguments[i]));
                    } catch (e) {
                        console.log('    arg[' + i + ']: [unserializable]');
                    }
                }

                var ret = overload.apply(this, arguments);

                try {
                    console.log('[+] Return: ' + JSON.stringify(ret));
                } catch (e) {
                    console.log('[+] Return: [unserializable]');
                }

                return ret;
            };
        });
    });
}


function hook_classloader() {
    Java.perform(function () {
        Java.enumerateClassLoaders({
            onMatch: function (loader) {
                try {
                    Java.classFactory.loader = loader; // 设置当前 ClassLoader
                    hookClass("yaq.pro");

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
