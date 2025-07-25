// com.example.app2
// frida -U -F  com.example.app2 -l common_hook.js  --runtime=v8
// frida -U -f  com.example.app2 -l common_hook.js
function showStacks() {
    console.log(
        Java.use("android.util.Log")
            .getStackTraceString(
                Java.use("java.lang.Throwable").$new()
            )
    );
}

Java.perform(function () {
    let searchingKey = "m9";
    // Hook ArrayList的add和addAll方法
    const mapClasses = ["java.util.HashMap", "java.util.LinkedHashMap", "java.util.TreeMap", "java.util.TreeMap"];
    mapClasses.forEach(className => {
        // hook put method

        Java.use(className).put.implementation = function (key, value) {
            // console.log("enter put");
            try {
                if (key.equals(searchingKey)) {
                    showStacks();
                    console.log("Key: " + key + " ,Value: " + value);
                }
                return this.put(key, value);
            } catch (e) {
                return this.put(key, value);
            }

        };

        // hook putAll method
        Java.use(className).putAll.implementation = function (map) {
            // console.log("enter putAll");
            try {
                if (map.containsValue(searchingKey)) {
                    showStacks();
                    let convertedMap = Java.cast(map, Java.use("java.util.HashMap"));
                    console.log("Map: " + convertedMap.toString());
                }
                return this.putAll(map);
            } catch (e) {
                return this.putAll(map);
            }

        };
    });
})
