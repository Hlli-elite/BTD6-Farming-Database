document.getElementById('fileInput').addEventListener('change', async (event) => {
    const file = event.target.files[0];
    if (!file) return;

    const buffer = await file.arrayBuffer();
    const status = document.getElementById('status');
    status.innerText = "Processing...";

    try {
        const salt = buffer.slice(52, 76);
        const encryptedData = buffer.slice(76);

        // Derive Key (PBKDF2)
        const password = new TextEncoder().encode('11');
        const baseKey = await crypto.subtle.importKey('raw', password, 'PBKDF2', false, ['deriveBits']);
        const derivedBits = await crypto.subtle.deriveBits(
            { name: 'PBKDF2', salt: salt, iterations: 10, hash: 'SHA-1' },
            baseKey, 256 // 32 bytes
        );

        const iv = derivedBits.slice(0, 16);
        const keyData = derivedBits.slice(16, 32);

        const key = await crypto.subtle.importKey('raw', keyData, 'AES-CBC', false, ['decrypt']);

        // Decrypt
        const decrypted = await crypto.subtle.decrypt({ name: 'AES-CBC', iv: iv }, key, encryptedData);

        // Decompress
        const decompressed = pako.inflate(new Uint8Array(decrypted));

        // Download
        const blob = new Blob([decompressed], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'Decrypted_Profile_5.json';
        a.click();
        
        status.innerText = "Done!";
    } catch (err) {
        status.innerText = "Error: " + err.message;
        console.error(err);
    }
});
