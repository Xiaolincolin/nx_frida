Java.perform(() => {
    const is64 = Process.pointerSize === 8;
    const JV_STRIDE = is64 ? 8 : 4;


    function getSymbol(name) {
        const mod = Process.getModuleByName("libart.so");
        for (const s of mod.enumerateSymbols()) {
            const n = s.name || "";
            if (n.indexOf("art") < 0) continue;
            if (n.indexOf("CheckJNI") >= 0) continue;
            if (n.indexOf("Notify") >= 0) continue;
            if (n.indexOf("mirror") >= 0) continue;
            if (n.indexOf("verifier") >= 0) continue;
            if (n.indexOf("DexFile") >= 0) continue;
            if (n.indexOf("JNIILb1") >= 0) continue;
            if (n.indexOf(name) >= 0) {
                console.log("[getSymbol] hit:", n, "=>", s.address);
                return s.address;
            }
        }
        return null;
    }

    // 只缓存 jmethodID -> {name, sig}
    const methodMap = {};
    const GetMethodID = getSymbol("GetMethodID");
    if (GetMethodID) {
        Interceptor.attach(GetMethodID, {
            onEnter(args) {
                this.name = Memory.readCString(args[2]);
                this.sig = Memory.readCString(args[3]);
            },
            onLeave(retval) {
                methodMap[retval.toString()] = {name: this.name, sig: this.sig};
            }
        });
    }

    function parseArgTypes(sig) {
        const L = sig.indexOf('(') + 1, R = sig.indexOf(')');
        const s = sig.slice(L, R);
        const out = [];
        for (let i = 0; i < s.length;) {
            const c = s[i];
            if ("BCDFIJSZ".indexOf(c) >= 0) {
                out.push(c);
                i++;
            } else if (c === 'L') {
                const j = s.indexOf(';', i);
                out.push(s.slice(i, j + 1));
                i = j + 1;
            } else if (c === '[') {
                let j = i;
                while (s[j] === '[') j++;
                if (s[j] === 'L') {
                    const k = s.indexOf(';', j);
                    out.push(s.slice(i, k + 1));
                    i = k + 1;
                } else {
                    out.push(s.slice(i, j + 1));
                    i = j + 1;
                }
            } else {
                out.push(c);
                i++;
            }
        }
        return out;
    }

    function readJValueRaw(ptr, type) {
        try {
            switch (type[0]) {
                case 'Z':
                    return Memory.readU8(ptr);
                case 'B':
                    return Memory.readS8(ptr);
                case 'C':
                    return Memory.readU16(ptr);
                case 'S':
                    return Memory.readS16(ptr);
                case 'I':
                    return Memory.readS32(ptr);
                case 'J':
                    return is64 ? Memory.readS64(ptr)
                        : (Memory.readS32(ptr) | (Memory.readS32(ptr.add(4)) * 0x100000000));
                case 'F':
                    return Memory.readFloat(ptr);
                case 'D':
                    return Memory.readDouble(ptr);
                case 'L':
                case '[':
                    return Memory.readPointer(ptr); // 对象只打印指针，避免 JNI 重入
                default:
                    return `(unknown ${type})`;
            }
        } catch (e) {
            return `(read error: ${e})`;
        }
    }

    const CallObjectMethodA_addr = getSymbol("CallObjectMethodA");
    if (!CallObjectMethodA_addr) {
        console.error("CallObjectMethodA symbol not found");
        return;
    }
    // const addr = getSymbol('CallVoidMethodA');
    const addr1 = getSymbol('CallObjectMethodA');
    // const addr2 = getSymbol('CallObjectMethodV');


    const add_list = [addr1];
    for (let a of add_list) {
        Interceptor.attach(a, {
            onEnter(args) {
                const mid = args[2];
                const av = args[3];
                const info = methodMap[mid.toString()];
                if (!info) {
                    this.skip = true;
                    return;
                }
                this.info = info;            // 给 onLeave 用
                this.av = av;              // 如果你还想打印参数
                this.types = parseArgTypes(info.sig);

                console.log(`\n[CallObjectMethodA] ${info.name}${info.sig}`);
                // 可选：打印参数（不触发 JNI）
                for (let i = 0; i < this.types.length; i++) {
                    const v = readJValueRaw(av.add(i * JV_STRIDE), this.types[i]);
                    const t = this.types[i];
                    console.log(`  arg[${i}]: ${t} = ${t[0] === 'L' || t[0] === '[' ? ('jobject@' + v) : v}`);
                    console.log("  => ", t);

                    if (t.endsWith("java/lang/String;")) {
                        const JSONObject = Java.use('java/lang/String');
                        const jsObj = Java.cast(v, JSONObject);
                        console.log("  => i Jstgring:", jsObj.toString());
                    }
                     if (t.endsWith("[B")) {
                        const ByteArray = Java.use('[B');
                        const jba = Java.cast(v, ByteArray);
                        const jsBytes = Java.array('byte', jba);

                        // 把 JS 数组转成 Frida Memory 里的 buffer
                        const buf = Memory.alloc(jsBytes.length);
                        for (let i = 0; i < jsBytes.length; i++) {
                            Memory.writeU8(buf.add(i), jsBytes[i] & 0xff);
                        }
                        console.log(`  => i byte[${jsBytes.length}] dump:`);
                        console.log(hexdump(buf, {length: jsBytes.length}));
                    }
                }
            },
            onLeave(retval) {
                if (this.skip) return;

                // 仅当返回类型是 Lorg/json/JSONObject; 时尝试转换打印
                const retIsJSONObject = this.info.sig.endsWith(")Lorg/json/JSONObject;");

                // 返回字符串
                const retIsString = this.info.sig.endsWith(")Ljava/lang/String;");

                // 返回bytes
                const retIsBytes = this.info.sig.endsWith(")[B");

                if (retIsJSONObject) {
                    try {
                        if (retval.isNull()) {
                            console.log("  => return null");
                            return;
                        }
                        // 使用 Frida Java 层来 cast + toString（比直接 env.* 稳）
                        const JSONObject = Java.use('org.json.JSONObject');
                        const jsObj = Java.cast(retval, JSONObject);
                        console.log("  => return JSONObject:", jsObj.toString());
                        const trace = Thread.backtrace(this.context, Backtracer.FUZZY)
                            .map(addr => DebugSymbol.fromAddress(addr).toString())
                            .join("\n");
                        console.log("[Call Stack]\n" + trace)
                    } catch (e) {
                        console.log(`  => JSONObject inspect failed: ${e}`);
                        console.log(`  => return jobject@${retval}`);
                    }
                } else if (retIsString) {
                    if (retval.isNull()) {
                        console.log("  => return null");
                        return;
                    }
                    // 使用 Frida Java 层来 cast + toString（比直接 env.* 稳）
                    const JSONObject = Java.use('java/lang/String');
                    const jsObj = Java.cast(retval, JSONObject);
                    console.log("  => return Jstgring:", jsObj.toString());
                    // const trace = Thread.backtrace(this.context, Backtracer.FUZZY)
                    //     .map(addr => DebugSymbol.fromAddress(addr).toString())
                    //     .join("\n");
                    // console.log("[Call Stack]\n" + trace)
                } else if (retIsBytes) {
                    try {
                        const ByteArray = Java.use('[B');
                        const jba = Java.cast(retval, ByteArray);
                        const jsBytes = Java.array('byte', jba);

                        // 把 JS 数组转成 Frida Memory 里的 buffer
                        const buf = Memory.alloc(jsBytes.length);
                        for (let i = 0; i < jsBytes.length; i++) {
                            Memory.writeU8(buf.add(i), jsBytes[i] & 0xff);
                        }
                        console.log("  => return byte[] dump:");
                        console.log(hexdump(buf, {length: jsBytes.length}));
                        const trace = Thread.backtrace(this.context, Backtracer.FUZZY)
                            .map(addr => DebugSymbol.fromAddress(addr).toString())
                            .join("\n");
                        console.log("[Call Stack]\n" + trace)
                    } catch (e) {
                        console.log(`  => dump error: ${e}`);
                    }

                } else {
                    console.log(`  => return ${retval.isNull() ? "null" : ("jobject@" + retval)}`);
                }


            }
        });
    }
});
