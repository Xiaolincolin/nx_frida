function hook_ola_m12() {
    const moduleName = "libgdtqone.so";
    const base = Module.findBaseAddress(moduleName);
    let address_list = [
        0xFDA8,
        0x1E3C0,
        0x1F258,
        0x1DB04,
        0x1E068,
        0x1812C,
        0x3DD80,
        0x111E0,
        0xAF08,
        0x48580,
        0x100E8,
        0xA8F8,
        0xB89C,
        0x476AC,
        0x1FE60,
        0x4972C,
        0x1F0E0,
        0x3C268,
        0xFF68,
        0x1DD60,
        0x484F0,
        0x13C40,
        0x11BCC,
        0x12F28,
        0x1491C,
        0x432E0,
        0x131B0,
        0x16FF0,
        0x14668,
        0x15844,
        0x13A10,
        0x43BDC,
        0x3AA20
    ]
    for (const offset of address_list) {
        let sub_addr = base.add(offset);
        Interceptor.attach(sub_addr, {
            onEnter: function (args) {
                console.log(`enter sub_${offset.toString(16)}`)
            },
            onLeave: function (retval) {
                console.log(`leave sub_${offset.toString(16)}`)
            }
        });
    }
}


function hook_system() {
    const libname = 'libgdtqone.so'; // 改成你的

    const waitForLib = () => {
        const m = Process.findModuleByName(libname);
        if (m) {
            console.log("🧬 Found", libname, "at", m.base);
            hook_ola_m12();
        } else {
            setTimeout(waitForLib, 100); // 重试
        }
    };

    waitForLib();

}


setImmediate(hook_system);
