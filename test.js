const { encrypt, decrypt } = require("./encrypt");

const payload = { username: "testUser" };

const runTest = () => {
    console.log("\n🔹 Generating Encrypted Token...");
    const encryptedToken = encrypt(payload);
    console.log("🔐 Encrypted Token:", encryptedToken);

    console.log("\n🔹 Decrypting Token...");
    const decryptedPayload = decrypt(encryptedToken);
    
    if (decryptedPayload) {
        console.log("✅ Success! Decrypted Payload:", decryptedPayload);
    } else {
        console.log("❌ Decryption Failed!");
    }
};

runTest();
