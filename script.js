document.getElementById('decryptButton').addEventListener('click', async function() {
    const fileInput = document.getElementById('fileInput');
    const output = document.getElementById('output');
    
    if (!fileInput.files[0]) {
        alert("Please upload a file first!");
        return;
    }

    const file = fileInput.files[0];
    const arrayBuffer = await file.arrayBuffer();
    const data = new Uint8Array(arrayBuffer);

    try {
        // Python: s = b[52:76], e = b[76:]
        const salt = CryptoJS.lib.WordArray.create(data.slice(52, 76));
        const encryptedData = CryptoJS.lib.WordArray.create(data.slice(76));
        const password = "11";

        // Python: P(algorithm=H.SHA1(), length=32, salt=s, iterations=10)
        const keyFull = CryptoJS.PBKDF2(password, salt, {
            keySize: 32 / 4,
            iterations: 10,
            hasher: CryptoJS.algo.SHA1
        });

        // Python: AES(k[16:32]), M.CBC(k[:16])
        // JS Note: Words are 4 bytes. k[0:16] is words 0-3, k[16:32] is words 4-7.
        const iv = CryptoJS.lib.WordArray.create(keyFull.words.slice(0, 4));
        const key = CryptoJS.lib.WordArray.create(keyFull.words.slice(4, 8));

        const decrypted = CryptoJS.AES.decrypt({ ciphertext: encryptedData }, key, {
            iv: iv,
            mode: CryptoJS.mode.CBC,
            padding: CryptoJS.pad.Pkcs7 // Common default
        });

        // Convert CryptoJS WordArray to Uint8Array for Pako (zlib)
        const decryptedUint8 = new Uint8Array(decrypted.sigBytes);
        for (let i = 0; i < decrypted.sigBytes; i++) {
            decryptedUint8[i] = (decrypted.words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
        }

        // Python: Z.decompress(o)
        const decompressed = pako.inflate(decryptedUint8);
        const textOutput = new TextDecoder().decode(decompressed);

        // Print first 100 letters
        output.textContent = "Preview: " + textOutput.substring(0, 100) + "...";
        console.log("Full Output:", textOutput);

    } catch (e) {
        console.error(e);
        output.textContent = "Error: Decryption failed. Ensure the file and password are correct.";
    }
});
