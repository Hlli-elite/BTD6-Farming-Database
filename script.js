document.addEventListener('DOMContentLoaded', function() {
    const decryptButton = document.getElementById('decryptButton');
    const fileInput = document.getElementById('fileInput');
    const output = document.getElementById('output');

    decryptButton.addEventListener('click', async function() {
        // Check if a file was actually selected
        if (fileInput.files.length === 0) {
            alert("Please upload a file first!");
            return;
        }

        const file = fileInput.files[0];
        const arrayBuffer = await file.arrayBuffer();
        const data = new Uint8Array(arrayBuffer);

        try {
            output.textContent = "Decrypting...";

            // 1. Extract Salt and Encrypted Payload (Matches Python b[52:76] and b[76:])
            const saltBytes = data.slice(52, 76);
            const encryptedBytes = data.slice(76);
            
            const salt = CryptoJS.lib.WordArray.create(saltBytes);
            const ciphertext = CryptoJS.lib.WordArray.create(encryptedBytes);

            // 2. PBKDF2 Key Derivation (Matches Python: SHA1, 10 iterations, 32 bytes, password '11')
            const k = CryptoJS.PBKDF2("11", salt, {
                keySize: 32 / 4,
                iterations: 10,
                hasher: CryptoJS.algo.SHA1
            });

            // Split key k: IV is first 16 bytes, Key is next 16 bytes
            const iv = CryptoJS.lib.WordArray.create(k.words.slice(0, 4));
            const key = CryptoJS.lib.WordArray.create(k.words.slice(4, 8));

            // 3. Decrypt AES-CBC (Using NoPadding to handle the raw stream like Python's cryptography lib)
            const decrypted = CryptoJS.AES.decrypt({ ciphertext: ciphertext }, key, {
                iv: iv,
                mode: CryptoJS.mode.CBC,
                padding: CryptoJS.pad.NoPadding 
            });

            // 4. Convert CryptoJS WordArray back to Uint8Array for decompression
            const decryptedUint8 = new Uint8Array(decrypted.sigBytes);
            for (let i = 0; i < decrypted.sigBytes; i++) {
                decryptedUint8[i] = (decrypted.words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
            }

            // 5. Zlib Decompress (Matches Python: Z.decompress)
            const decompressed = pako.inflate(decryptedUint8);
            const textOutput = new TextDecoder().decode(decompressed);

            // Output the result
            output.textContent = "Preview (First 100 chars): " + textOutput.substring(0, 100);
            console.log("Full Decrypted JSON:", textOutput);

        } catch (err) {
            console.error("Error during decryption:", err);
            output.textContent = "Error: Decryption failed. Check file format or console.";
        }
    });
});
