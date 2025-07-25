function print_map(data) {
    Java.perform(function () {
        let Map = Java.use("java.util.Map");
        let result = Java.cast(data, Map);
        console.log(JSON.stringify(result));
    });
}

function hook_20688(baseAddr) {
    const addr = baseAddr.add(0x20688);
    Interceptor.attach(addr, {
        onEnter(args) {
            console.log("hook_20688 onEnter");
            console.log('a5:')
            print_map(args[4]);
            console.log('a6:')
            console.log(args[5].toInt32())
        },
        onLeave(retval) {
            console.log("hook_20688 onLeave");
        }
    });
}

function hook_main(libname) {
    const baseAddr = Module.findBaseAddress(libname);
    if (!baseAddr) {
        console.error("❌ 未找到模块:", libname);
        return;
    }
    console.log('baseAddr:', baseAddr);
    hook_20688(baseAddr);
}

function hook_system() {
    const libname = "libturingau.3e364a2a.so";

    const waitForLib = () => {
        const m = Process.findModuleByName(libname);
        if (m) {
            console.log("🧬 Found", libname, "at", m.base);
            hook_main(libname);
        } else {
            setTimeout(waitForLib, 50); // 重试
        }
    };

    waitForLib();

}


setImmediate(hook_system);

