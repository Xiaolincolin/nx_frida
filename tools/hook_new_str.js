function hook_new_str() {
    // 替换为你的目标模块名
    var symbols = Process.getModuleByName("libart.so").enumerateSymbols();
    var addr_GetStringUTFChars = NULL;
    for (var index = 0; index < symbols.length; index++) {
        const symbols_one = symbols[index];
        if (symbols_one.name.indexOf("art") >= 0) {
            if (symbols_one.name.indexOf("checkJNI") === -1 && symbols_one.name.indexOf("NewStringUTF") >= 0) {
                console.log("NewStringUTF ", JSON.stringify(symbols_one));
                addr_GetStringUTFChars = symbols_one.address;
                console.log("NewStringUTF address = " + addr_GetStringUTFChars);
                break
            }
        }
    }
    Interceptor.attach(addr_GetStringUTFChars, {
        onEnter: function (args) {
            var env = args[0];
            var param1 = args[1];
            console.log("env :", env, "param1 ", ptr(param1).readCString());
        }, onLeave: function (retval) {
            console.log("addr_NewStringUTF retval :", Java.vm.getEnv().getStringUtfChars(retval, null).readCString());
        }
    })


}

setImmediate(hook_new_str)