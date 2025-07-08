function byteArrayToBase64(byteArray) {
    return Java.use("android.util.Base64").encodeToString(byteArray, 0);
}


function byteArrayToUtf8(byteArray) {
    try {
        return Java.use("java.lang.String").$new(byteArray).toString();
    } catch (e) {
        return "[无法转换为UTF-8字符串]";
    }
}

function byteArrayToHexString(byteArray) {
    const HEX_CHARS = '0123456789abcdef';
    let hexString = '';

    for (let i = 0; i < byteArray.length; i++) {
        const code = byteArray[i] & 0xff;
        hexString += HEX_CHARS.charAt(code >> 4) + HEX_CHARS.charAt(code & 0xf);
    }

    return hexString;
}
