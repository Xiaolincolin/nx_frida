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

                // break
            }
        }
    }
}

const methodCache = {};

function getMethodName(env, clazz, methodID) {
    const hash = methodID.toString();
    if (methodCache[hash]) {
        return methodCache[hash];
    }

    try {
        // 获取 Method 对象
        const jclass = env.getObjectClass(clazz);
        const getMethodName = env.getMethodID("java/lang/reflect/Method", "getName", "()Ljava/lang/String;");
        const toStringID = env.getMethodID("java/lang/reflect/Method", "toString", "()Ljava/lang/String;");
        const reflectMethod = env.fromReflectedMethod(methodID);
        const methodNameJstr = env.callObjectMethod(reflectMethod, getMethodName);
        const methodName = env.getStringUtfChars(methodNameJstr, null).readCString();

        const className = Java.classFactory.get(classNameFor(env, clazz));
        const fullMethod = className + "." + methodName;
        methodCache[hash] = fullMethod;
        return fullMethod;
    } catch (e) {
        return "unknown";
    }
}

// 使用 jclass 获取类名
function classNameFor(env, jclass) {
    try {
        const classClass = env.getObjectClass(jclass);
        const getName = env.getMethodID(classClass, "getName", "()Ljava/lang/String;");
        const nameObj = env.callObjectMethod(jclass, getName);
        return env.getStringUtfChars(nameObj, null).readCString();
    } catch (e) {
        return "unknown.class";
    }
}

Java.perform(function () {
    const env = Java.vm.getEnv();
    const vtablePtr = env.handle.readPointer();
    const CallObjectMethodV_ptr = vtablePtr.add(36 * Process.pointerSize).readPointer();
    const CallLongMethodV_ptr = vtablePtr.add(46 * Process.pointerSize).readPointer();

    Interceptor.attach(CallObjectMethodV_ptr, {
        onEnter: function (args) {
            this.env = Java.vm.getEnv();
            this.obj = args[1];
            this.methodId = args[2];
        },
        onLeave: function (retval) {
            try {
                const methodInfo = getMethodName(this.env, this.obj, this.methodId);
                const resultStr = this.env.getStringUtfChars(retval, null).readCString();
                console.log("📞 CallObjectMethodV 调用", methodInfo, "返回 =", resultStr);
            } catch (e) {
                console.log("⚠️ CallObjectMethodV 调用失败");
            }
        }
    });

    Interceptor.attach(CallLongMethodV_ptr, {
        onEnter: function (args) {
            this.env = Java.vm.getEnv();
            this.obj = args[1];
            this.methodId = args[2];
        },
        onLeave: function (retval) {
            try {
                const methodInfo = getMethodName(this.env, this.obj, this.methodId);
                console.log("⏱️ CallLongMethodV 调用", methodInfo, "返回 =", retval.toInt64());
            } catch (e) {
                console.log("⚠️ CallLongMethodV 调用失败");
            }
        }
    });
});

