function find_x5_target_func() {
    // 寻找x5指向函数的地址
    Java.perform(() => {
        const moduleName = "libyaqbasic.3e364a2a.so";  // 你的so名字改这里
        const baseAddr = Module.findBaseAddress(moduleName);
        if (!baseAddr) {
            console.error("[!] 找不到模块:", moduleName);
            return;
        }
        console.log("[*]", moduleName, "基址:", baseAddr);

        const off_addr = baseAddr.add(0x121E8);
        console.log("[*] off_121E8 绝对地址:", off_addr);

        const func_ptr = Memory.readPointer(off_addr);
        console.log("[*] off_121E8 指向的函数地址:", func_ptr);
        const module = Process.findModuleByAddress(func_ptr);
        if (module) {
            const offset = func_ptr.sub(module.base);
            console.log("[*] 函数位于模块:", module.name);
            console.log("[*] 模块基址:", module.base);
            console.log("[*] 函数相对偏移:", offset);
        } else {
            console.warn("[!] 无法识别该地址所在的模块:", func_ptr);
        }

        // 找到x5指向的函数地址后，hook这个函数查看传参
        Interceptor.attach(func_ptr, {
            onEnter(args) {
                console.log("[*] getobjresult called");
                // 前两个参数通常是jniEnv和jobject/jclass，跳过它们
                console.log("    第1个参数:", args[2].toInt32());
                console.log("    第2个参数:", args[3].toInt32());
                console.log("    objArr:", args[4]);
            },
            onLeave(retval) {
                console.log("[*] getobjresult 返回值:", retval);
            }
        });
    })
}

function hook_target_func() {
    // 已经找打真正的函数了，hook这个函数
    Java.perform(() => {
        const moduleName = "libyaqpro.3e364a2a.so";  // 你的so名字改这里
        const baseAddr = Module.findBaseAddress(moduleName);
        if (!baseAddr) {
            console.error("[!] 找不到模块:", moduleName);
            return;
        }
        console.log("[*]", moduleName, "基址:", baseAddr);

        const off_addr = baseAddr.add(0xb484);
        console.log("[*] sub_B484 绝对地址:", off_addr);

        Interceptor.attach(off_addr, {
            onEnter(args) {
                let code_id = args[2].toInt32();
                this.code_id = code_id;
                if (code_id === 305) {
                    // 前两个参数通常是jniEnv和jobject/jclass，跳过它们
                    console.log("    第1个参数:", code_id);
                    console.log("    第2个参数:", args[3].toInt32());
                    console.log("    objArr:", args[4]);
                }
            },
            onLeave(retval) {
                if (this.code_id === 305) {
                    console.log("[*] getobjresult 返回值:", retval);
                }
            }
        });

    })
}

function inline_hook_ret() {
    Java.perform(() => {
        const moduleName = "libyaqbasic.3e364a2a.so";  // 你的so名字改这里
        const baseAddr = Module.findBaseAddress(moduleName);
        if (!baseAddr) {
            console.error("[!] 找不到模块:", moduleName);
            return;
        }
        console.log("[*]", moduleName, "基址:", baseAddr);

        const off_addr = baseAddr.add(0x7CDC0);
        console.log("[*] off_7CDC0 绝对地址:", off_addr);

        const func_ptr = Memory.readPointer(off_addr);
        console.log("[*] off_7CDC0 指向的函数地址:", func_ptr);
        const module = Process.findModuleByAddress(func_ptr);
        if (module) {
            const offset = func_ptr.sub(module.base);
            console.log("[*] 函数位于模块:", module.name);
            console.log("[*] 模块基址:", module.base);
            console.log("[*] 函数相对偏移:", offset);
        } else {
            console.warn("[!] 无法识别该地址所在的模块:", func_ptr);
        }

        // 找到x5指向的函数地址后，hook这个函数查看传参
        // Interceptor.attach(func_ptr, {
        //     onEnter(args) {
        //         console.log("[*] getobjresult called");
        //         // 前两个参数通常是jniEnv和jobject/jclass，跳过它们
        //         console.log("    第1个参数:", args[2].toInt32());
        //         console.log("    第2个参数:", args[3].toInt32());
        //         console.log("    objArr:", args[4]);
        //     },
        //     onLeave(retval) {
        //         console.log("[*] getobjresult 返回值:", retval);
        //     }
        // });
    })


}

function hook_mu_p_main() {
    // 第一步，根据动态注册，找到了函数getobjresult所在的so以及offset
    // 调用register native就好了


    // 第二步，根据分析，是这儿函数在base.so中是注册式函数，并不是真正的函数，需要在jni_onload中绑定
    /*
        .text:0000000000000A6C                 ADRP            X5, #off_11FF0@PAGE
        .text:0000000000000A70                 STP             X29, X30, [SP,#-0x10+var_s0]!
        .text:0000000000000A74                 MOV             X29, SP
        .text:0000000000000A78                 LDR             X5, [X5,#off_11FF0@PAGEOFF]
        .text:0000000000000A7C                 LDR             X5, [X5]
        .text:0000000000000A80                 BLR             X5
        .text:0000000000000A84                 LDP             X29, X30, [SP+var_s0],#0x10
        .text:0000000000000A88                 RET
        .text:0000000000000A88 ; } // starts at A6C
    * */


    // 第三步，X5指向了off_11FF0的地址，所以我们需要找到off_11FF0的地址，然后找到off_11FF0指向的函数地址，然后hook这个函数
    /*
        [*] libyaqbasic.3e364a2a.so 基址: 0x774346a000
        [*] off_121E8 绝对地址: 0x774347c1e8
        [*] off_121E8 指向的函数地址: 0x774390d484
        [*] 函数位于模块: libyaqpro.3e364a2a.so
        [*] 模块基址: 0x7743902000
        [*] 函数相对偏移: 0xb484
    * */
    // find_x5_target_func();

    // 第四步，hook off_11FF0指向的函数
    // hook_target_func()
    inline_hook_ret()
}

setImmediate(hook_mu_p_main);
