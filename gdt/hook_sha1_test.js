function hook_sha1_test() {
    const base = Module.findBaseAddress("libyaqpro.3e364a2a.so");
    if (!base) {
        console.log('not found base')
        return
    }
    const sub_597E8 = base.add(0x597E8)
    Interceptor.attach(sub_597E8, {
        onEnter(args) {
            this.arg5 = args[4];
        },

        onLeave(retval) {
            const buf = Memory.readByteArray(this.arg5, 32);  // ptr 是返回数据地址，40 是你已知的长度
            console.log("leave sub_597E8 ", hexdump(buf));
        }
    });
    const sub_5505C = base.add(0x5505C)
    Interceptor.attach(sub_5505C, {
        onEnter(args) {
            let arg2 = args[1];
            console.log('enter sub_5505C 明文', hexdump(arg2))
        },

        onLeave(retval) {
        }
    });

}

setImmediate(hook_sha1_test);
