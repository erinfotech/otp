// Nodejs encryption with CTR
const crypto = require('crypto');
const algorithm = process.env.ALGORITHM || 'aes-256-cbc';
const salt = crypto.randomBytes(32);
const key = crypto.scryptSync(process.env.SECRET, salt, 32);;
const iv = crypto.randomBytes(16);

const encrypt = function (text) {
 let cipher = crypto.createCipheriv(algorithm, Buffer.from(key), iv);
 let encrypted = cipher.update(text);

 encrypted = Buffer.concat([encrypted, cipher.final()]);

 return { iv: iv.toString('hex'), encryptedData: encrypted.toString('hex') };
};

const decrypt = function (encrypted) {
    try {
        let iv = Buffer.from(encrypted.iv, 'hex');
        let encryptedText = Buffer.from(encrypted.encryptedData, 'hex');
        let decipher = crypto.createDecipheriv(algorithm, Buffer.from(key), iv);
        let decrypted = decipher.update(encryptedText);

        decrypted = Buffer.concat([decrypted, decipher.final()]);

        return decrypted.toString();
    } catch (err) {
        console.log(err.toString());
        return null;
    }
};

module.exports = { encrypt, decrypt };