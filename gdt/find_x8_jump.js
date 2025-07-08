function hook_inline() {
    const baseAddr = Module.findBaseAddress("libyaqpro.3e364a2a.so");
    console.log('baseAddr: ', baseAddr)
    const sub_B484 = baseAddr.add(0xB484);
    const sub_1AD18 = baseAddr.add(0x1AD18);
    const off_77670 = baseAddr.add(0x77670);

    const trackedThreads = {};

    Interceptor.attach(sub_B484, {
        onEnter(args) {
            const codeId = args[2].toInt32();  // a3
            if (codeId === 213) {
                trackedThreads[this.threadId] = true;
                console.log(`🔥 sub_B484 called with codeId = ${codeId}`);
            }
        },
        onLeave() {
            delete trackedThreads[this.threadId];
        }
    });

    Interceptor.attach(sub_1AD18, {
        onEnter(args) {
            if (!trackedThreads[this.threadId]) return;

            try {
                const structPtr = args[1];  // X1, 也就是 a2
                const x23_ptr = structPtr.add(8);   // X23 = *(a2 + 8)
                const typeId = Memory.readU16(x23_ptr) & 0xFF;

                const jumpEntry = off_77670.add(typeId * 8);
                const targetAddr = Memory.readPointer(jumpEntry);

                console.log(`🔁 [213 only] typeId = ${typeId} → off_77670[${typeId}] = ${targetAddr},offset = ${targetAddr.sub(baseAddr)}`);
            } catch (e) {
                console.warn("⚠️ Error extracting typeId:", e);
            }
        }
    });


}

setImmediate(hook_inline)
