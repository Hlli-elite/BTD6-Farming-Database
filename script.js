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
        // 1. Extract Salt and Encrypted Payload
        const saltBytes = data.slice(52, 76);
        const encryptedBytes = data.slice(76);
        
        const salt = CryptoJS.lib.WordArray.create(saltBytes);
        const ciphertext = CryptoJS.lib.WordArray.create(encryptedBytes);

        // 2. PBKDF2 Key Derivation (Matches Python: SHA1, 10 iterations, 32 bytes)
        const k = CryptoJS.PBKDF2("11", salt, {
            keySize: 32 / 4,
            iterations: 10,
            hasher: CryptoJS.algo.SHA1
        });

        // Python logic: IV is k[:16] (words 0-3), Key is k[16:32] (words 4-7)
        const iv = CryptoJS.lib.WordArray.create(k.words.slice(0, 4));
        const key = CryptoJS.lib.WordArray.create(k.words.slice(4, 8));

        // 3. Decrypt AES-CBC (Using NoPadding to avoid crashes)
        const decrypted = CryptoJS.AES.decrypt({ ciphertext: ciphertext }, key, {
            iv: iv,
            mode: CryptoJS.mode.CBC,
            padding: CryptoJS.pad.NoPadding 
        });

        // 4. Convert WordArray to Uint8Array for Decompression
        const decryptedUint8 = new Uint8Array(decrypted.sigBytes);
        for (let i = 0; i < decrypted.sigBytes; i++) {
            decryptedUint8[i] = (decrypted.words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
        }

        // 5. Zlib Decompress (Matches Python: Z.decompress)
        const decompressed = pako.inflate(decryptedUint8);
        const textOutput = new TextDecoder().decode(decompressed);

        output.textContent = "Success! Preview: " + textOutput.substring(0, 100);
        console.log("Full Decrypted String:", textOutput);

    } catch (err) {
        console.error("Detailed Error:", err);
        output.textContent = "Error: Check the browser console (F12) for details. It's likely a padding or file-format error.";
    }
});
