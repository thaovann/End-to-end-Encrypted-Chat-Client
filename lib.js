const crypto = require("node:crypto");
const { subtle } = require("node:crypto").webcrypto;

const govEncryptionDataStr = "AES-GENERATION";

function bufferToString(arr) {
  return Buffer.from(arr).toString();
}

function genRandomSalt(len = 16) {
  return crypto.getRandomValues(new Uint8Array(len));
}

async function cryptoKeyToJSON(cryptoKey) {
  const key = await subtle.exportKey("jwk", cryptoKey);
  return key;
}

async function generateEG() {
  const keyPair = await subtle.generateKey(
    {
      name: "ECDH",
      namedCurve: "P-384", // Sử dụng đường cong thích hợp
    },
    true, // Cho phép xuất khóa
    ["deriveKey"] // Chỉ định key usage
  );
  return {
    pub: keyPair.publicKey, // Khóa công khai
    sec: keyPair.privateKey, // Khóa bí mật
  };
}



async function computeDH(privateKey, publicKey) {
  // Derive the shared secret using your private key and the recipient's public key
  return subtle.deriveBits(
    {
      name: "ECDH",
      public: publicKey,  // recipient's public key
    },
    privateKey, // your private key
    256 // The length in bits of the derived shared secret (usually 256 bits for ECDH)
  );
}



async function verifyWithECDSA(publicKey, message, signature) {
  return await subtle.verify(
    { name: "ECDSA", hash: { name: "SHA-384" } },
    publicKey,
    signature,
    Buffer.from(message)
  );
}

async function HMACtoAESKey(key, data, exportToArrayBuffer = false) {
  const hmacBuf = await subtle.sign({ name: "HMAC" }, key, Buffer.from(data));

  const out = await subtle.importKey("raw", hmacBuf, "AES-GCM", true, [
    "encrypt",
    "decrypt",
  ]);

  if (exportToArrayBuffer) {
    return await subtle.exportKey("raw", out);
  }

  return out;
}

async function HMACtoHMACKey(key, data) {
  const hmacBuf = await subtle.sign({ name: "HMAC" }, key, Buffer.from(data));
  return await subtle.importKey(
    "raw",
    hmacBuf,
    { name: "HMAC", hash: "SHA-256", length: 256 },
    true,
    ["sign"]
  );
}

async function HKDF(inputKey, salt, infoStr) {
  const inputKeyBuf = await subtle.sign(
    { name: "HMAC" },
    inputKey,
    Buffer.from("0")
  );
  const inputKeyHKDF = await subtle.importKey(
    "raw",
    inputKeyBuf,
    "HKDF",
    false,
    ["deriveKey"]
  );

  const salt1 = await subtle.sign({ name: "HMAC" }, salt, Buffer.from("salt1"));
  const salt2 = await subtle.sign({ name: "HMAC" }, salt, Buffer.from("salt2"));

  const hkdfOut1 = await subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: salt1, info: Buffer.from(infoStr) },
    inputKeyHKDF,
    { name: "HMAC", hash: "SHA-256", length: 256 },
    true,
    ["sign"]
  );

  const hkdfOut2 = await subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: salt2, info: Buffer.from(infoStr) },
    inputKeyHKDF,
    { name: "HMAC", hash: "SHA-256", length: 256 },
    true,
    ["sign"]
  );

  return [hkdfOut1, hkdfOut2];
}

async function encryptWithGCM(key, plaintext, iv, authenticatedData = "") {
  return await subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: Buffer.from(authenticatedData) },
    key,
    Buffer.from(plaintext)
  );
}

async function decryptWithGCM(key, ciphertext, iv, authenticatedData = "") {
  return await subtle.decrypt(
    { name: "AES-GCM", iv, additionalData: Buffer.from(authenticatedData) },
    key,
    ciphertext
  );
}

async function generateECDSA() {
  const keypair = await subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-384" },
    true,
    ["sign", "verify"]
  );
  const keypairObject = { pub: keypair.publicKey, sec: keypair.privateKey };
  return keypairObject;
}

async function signWithECDSA(privateKey, message) {
  return await subtle.sign(
    { name: "ECDSA", hash: { name: "SHA-384" } },
    privateKey,
    Buffer.from(message)
  );
}

module.exports = {
  govEncryptionDataStr,
  bufferToString,
  genRandomSalt,
  cryptoKeyToJSON,
  generateEG,
  computeDH,
  verifyWithECDSA,
  HMACtoAESKey,
  HMACtoHMACKey,
  HKDF,
  encryptWithGCM,
  decryptWithGCM,
  generateECDSA,
  signWithECDSA,
};
