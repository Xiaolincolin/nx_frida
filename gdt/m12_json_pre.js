let libName = "libgdtqone.so"


function readInlineStr(ptrValue) {
    const tag = ptrValue.readU64();
    if ((tag & 1) === 0) return null; // 非内联
    const length = tag >>> 1;
    const buf = ptrValue.add(8);
    return buf.readUtf8String(length);
}

function parseMap(mapPtr) {
    const begin = mapPtr.add(72).readPointer();
    const end = mapPtr.add(80).readPointer();

    console.log('[*] map begin =', begin, 'end =', end);
    let node = begin;

    while (!node.isNull() && !node.equals(end)) {
        try {
            const keyStruct = node.add(0x20);
            const valStruct = node.add(0x38);

            const keyTag = keyStruct.readU64();
            const valTag = valStruct.readU64();

            const key = (keyTag & 1)
                ? readInlineStr(keyStruct)
                : '[heap @ ' + keyStruct.add(8).readPointer() + ']';

            const val = (valTag & 1)
                ? readInlineStr(valStruct)
                : '[heap @ ' + valStruct.add(8).readPointer() + ']';

            console.log(`  ⇒ key: ${key}\n     val: ${val}`);

            // 红黑树遍历：找下一个 node
            let next = node.readPointer(); // left
            if (!next.isNull()) {
                while (next.readPointer() !== NULL) next = next.readPointer(); // 最左侧子树
                node = next;
            } else {
                let parent = node.add(0x10).readPointer();
                while (!parent.isNull() && node.equals(parent.add(0))) {
                    node = parent;
                    parent = parent.add(0x10).readPointer();
                }
                node = parent;
            }
        } catch (e) {
            console.log('  [!] Error parsing node @', node, e);
            break;
        }
    }
}


function hook_inline() {
    const base = Module.findBaseAddress(libName);
    if (!base) {
        console.log('not found base')
        return
    }


    const sub_1C71C_addr = base.add(0x1C670);
    console.log(`sub_1C71C_addr=${sub_1C71C_addr}`)

    Interceptor.attach(sub_1C71C_addr, {
        onEnter(args) {
            const a2 = args[2];

            // key 通常在结构开头 inline，直接读字符串（或调试确认）
            try {
                const keyStr = a2.readUtf8String();
                const type = a2.add(0x78).readU32();
                const valPtr = a2.add(0x30).readPointer();

                console.log(`[sub_1C71C] Key: ${keyStr}`);
                console.log(`  Type: ${type}`);

                if (type === 1) {
                    const valStr = Memory.readUtf8String(valPtr);
                    console.log(`  Value: ${valStr}`);
                } else {
                    console.log(`  Value Ptr: ${valPtr}`);
                }
            } catch (e) {
                console.log(`[sub_1C71C] Decode error: ${e}`);
            }
        }
    });


}

function hook_system() {
    const libname = libName; // 改成你的

    const waitForLib = () => {
        const m = Process.findModuleByName(libname);
        if (m) {
            console.log("🧬 Found", libname, "at", m.base);
            hook_inline();
        } else {
            setTimeout(waitForLib, 100); // 重试
        }
    };

    waitForLib();

}


setImmediate(hook_system);
