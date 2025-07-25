function hookNet() {
    Java.perform(function () {
        // 不走cronet，抓包使用
        var targetClass = 'org.chromium.CronetClient';
        var methodName = 'tryCreateCronetEngine';
        var gclass = Java.use(targetClass);
        gclass[methodName].overload('android.content.Context', 'boolean', 'boolean', 'boolean', 'boolean', 'java.lang.String', 'java.util.concurrent.Executor', 'boolean').implementation = function (context, z, z2, z3, z4, str, executor, z5) {
            console.log(`CronetClient.tryCreateCronetEngine is called: context=${context}, z=${z}, z2=${z2}, z3=${z3}, z4=${z4}, str=${str}, executor=${executor}, z5=${z5}`);
        }
    })
}

hookNet()
