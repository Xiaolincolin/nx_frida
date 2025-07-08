function showStacks() {
    console.log(
        Java.use("android.util.Log")
            .getStackTraceString(
                Java.use("java.lang.Throwable").$new()
            )
    );
}

function hook_mu_p_a_w() {

    let v1 = Java.use("com.qq.e.comm.plugin.v1");
    v1["a"].overload('com.qq.e.comm.plugin.sv', 'com.qq.e.comm.plugin.q1', 'com.qq.e.comm.plugin.u1').implementation = function (svVar, q1Var, u1Var) {
        console.log(`v1.a is called: svVar=${svVar}, q1Var=${q1Var}, u1Var=${u1Var}`);
        let w = u1Var.w()
        console.log(`v1.a w=${JSON.stringify(w)}`);
        let result = this["a"](svVar, q1Var, u1Var);
        console.log(`v1.a result=${JSON.stringify(result)}`);
        return result;
    };
}

function hook_mu_p_a() {
    let r2 = Java.use("com.qq.e.comm.plugin.r2");
    r2["a"].overload('java.lang.String').implementation = function (str) {
        console.log(`r2.a is called: str=${str}`);
        let b2 = this.b(null, str, 4);
        console.log('r2.a b2:', b2);
        let result = this["a"](str);
        console.log(`r2.a result=${result}`);
        return result;
    };
}


function hook_mu_p_c_u2_a() {
    console.log('hook_mu_p_c_u2_a');
    let i0 = Java.use("com.qq.e.comm.plugin.i0");
    i0["a"].overload('com.qq.e.comm.plugin.t2', 'int').implementation = function (t2Var, i) {
        console.log(`i0.a is called: t2Var=${t2Var}, i=${i}`);
        console.log('i0.a t2Var:', t2Var.w.value);
        let result = this["a"](t2Var, i);
        console.log(`i0.a result=${result}`);
        return result;
    };
}

function hook_mu_p_b() {
    let ia = Java.use("com.qq.e.comm.plugin.ia");
    ia["a"].implementation = function () {
        console.log(`ia.a is called`);
        let result = this["a"]();
        console.log(`ia.a result=${result.R.value}`);
        return result;
    };
}

function hook_classloader() {
    Java.perform(function () {
        Java.enumerateClassLoaders({
            onMatch: function (loader) {
                try {
                    Java.classFactory.loader = loader; // 设置当前 ClassLoader
                    hook_mu_p_b();

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
