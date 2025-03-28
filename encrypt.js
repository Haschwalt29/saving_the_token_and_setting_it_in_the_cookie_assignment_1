const crypto = require("crypto");
const jwt = require("jsonwebtoken");
require("dotenv").config();

// Setup encryption keys and constants
const SECRET_KEY = process.env.JWT_SECRET || "supersecretkey";
const ENCRYPTION_KEY = crypto.scryptSync(process.env.ENCRYPTION_SECRET || "encryptionkey", "salt", 32);
const IV_LENGTH = 16; // Initialization Vector size

// Encrypt the payload and return the token
const encrypt = (payload) => {
    try {
        // Create a JWT token
        const token = jwt.sign(payload, SECRET_KEY, { expiresIn: "1h" });

        // Generate IV
        const iv = crypto.randomBytes(IV_LENGTH);
        const cipher = crypto.createCipheriv("aes-256-cbc", ENCRYPTION_KEY, iv);

        // Encrypt the token
        let encrypted = cipher.update(token, "utf8", "hex");
        encrypted += cipher.final("hex");

        // Return IV + encrypted token
        return iv.toString("hex") + encrypted;
    } catch (error) {
        console.error("Encryption failed:", error);
        return null;
    }
};

// Decrypt the encrypted token and return the original payload
const decrypt = (encryptedToken) => {
    try {
        // Extract IV and encrypted token
        const iv = Buffer.from(encryptedToken.slice(0, IV_LENGTH * 2), "hex");
        const encryptedText = encryptedToken.slice(IV_LENGTH * 2);

        const decipher = crypto.createDecipheriv("aes-256-cbc", ENCRYPTION_KEY, iv);

        // Decrypt the token
        let decrypted = decipher.update(encryptedText, "hex", "utf8");
        decrypted += decipher.final("utf8");

        // Verify JWT token
        return jwt.verify(decrypted, SECRET_KEY);
    } catch (error) {
        console.error("Decryption failed:", error);
        return null;
    }
};

module.exports = { encrypt, decrypt };
