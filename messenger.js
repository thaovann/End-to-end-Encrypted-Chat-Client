/** ******* Imports ********/

const {
  bufferToString,
  genRandomSalt,
  generateEG, // async
  computeDH, // async
  verifyWithECDSA, // async
  HMACtoAESKey, // async
  encryptWithGCM, // async
  decryptWithGCM,
  cryptoKeyToJSON, // async
  govEncryptionDataStr,
  generateECDSA, // Add this line
  signWithECDSA, // If you need this as well
} = require("./lib");
const { subtle } = require("node:crypto").webcrypto;

class MessengerClient {
  constructor(certAuthorityPublicKey, govPublicKey) {
    this.caPublicKey = certAuthorityPublicKey;
    this.govPublicKey = govPublicKey;
    this.conns = {}; // data for each active connection
    this.certs = {}; // certificates of other users
    this.EGKeyPair = {}; // keypair from generateEG
  }

  /**
   * Generate a certificate to be stored with the certificate authority.
   * The certificate must contain the field "username".
   *
   * Arguments:
   *   username: string
   *
   * Return Type: certificate object/dictionary
   */
  async generateCertificate(username) {
    const { pub, sec } = await generateECDSA(); // generate ECDSA key pair
    const certificate = {
      username,
      publicKey: await cryptoKeyToJSON(pub), // Export the public key in JWK format
      issuedAt: Date.now(),
    };
    const certificateString = JSON.stringify(certificate);
    const signature = await signWithECDSA(sec, certificateString); // Sign the certificate with the private key
    certificate.signature = Buffer.from(signature); // Add the signature to the certificate
    return certificate;
  }

  /**
   * Receive and store another user's certificate.
   *
   * Arguments:
   *   certificate: certificate object/dictionary
   *   signature: ArrayBuffer
   *
   * Return Type: void
   */
  async receiveCertificate(certificate, signature) {
    const certificateString = JSON.stringify(certificate);
    const valid = await verifyWithECDSA(
      this.caPublicKey,
      certificateString,
      signature
    ); // Verify with the CA public key
    if (valid) {
      this.certs[certificate.username] = certificate; // Store the certificate
    } else {
      throw new Error("Certificate verification failed");
    }
  }

  /**
   * Generate the message to be sent to another user.
   *
   * Arguments:
   *   name: string
   *   plaintext: string
   *
   * Return Type: Tuple of [dictionary, ArrayBuffer]
   */
  async sendMessage(name, plaintext) {
  const recipientCert = this.certs[name];
  if (!recipientCert) {
    throw new Error("Recipient certificate not found");
  }

  // Update the public key to allow deriveKey
  const updatedPublicKey = {
    ...recipientCert.publicKey,
    key_ops: ["deriveKey"], // Ensure 'key_ops' for key derivation
  };

  try {
    // Import recipient's public key for ECDH with P-384 curve
    const recipientPublicKey = await subtle.importKey(
      "jwk", // Format: JSON Web Key
      updatedPublicKey, // The recipient's public key (updated)
      { name: "ECDH", namedCurve: "P-384" }, // ECDH algorithm with P-384 curve
      false, // Don't allow the key to be exported
      [] // Public keys should not have 'deriveBits' usage
    );
    console.log("Imported Recipient Public Key:", recipientPublicKey);

    // Generate your own ECDH key pair
    const { pub: myPub, sec: mySec } = await generateEG(); // Generate your ECDH key pair
    this.EGKeyPair = { pub: myPub, sec: mySec };

    console.log("Generated My Key Pair:", { pub: myPub, sec: mySec });

    // Compute shared secret using your private key and the recipient's public key
    const sharedSecret = await computeDH(mySec, recipientPublicKey);
    console.log("Computed Shared Secret:", sharedSecret);

    // Derive AES key from shared secret using HMAC
    const aesKey = await HMACtoAESKey(sharedSecret, govEncryptionDataStr);

    // Generate random IV for AES-GCM encryption
    const iv = genRandomSalt(12);
    const ciphertext = await encryptWithGCM(aesKey, plaintext, iv);

    // Prepare header with IV for later decryption
    const header = { iv };
    return [header, ciphertext];
  } catch (error) {
    console.error("Error in sendMessage:", error);
    throw error;
  }
}

async receiveMessage(name, [header, ciphertext]) {
  const senderCert = this.certs[name];
  if (!senderCert) {
    throw new Error("Sender certificate not found");
  }

  // Import sender's public key for ECDH with P-384 curve
  const senderPublicKey = await subtle.importKey(
    "jwk", // Format: JSON Web Key
    senderCert.publicKey, // The sender's public key
    { name: "ECDH", namedCurve: "P-384" }, // ECDH algorithm with P-384 curve
    false, // Don't allow the key to be exported
    [] // Public keys should not have 'deriveKey' usage
  );

  // Use your ECDH key pair to compute the shared secret
  const { pub: myPub, sec: mySec } = this.EGKeyPair; // Your ECDH key pair
  const sharedSecret = await computeDH(mySec, senderPublicKey);
  console.log("Computed Shared Secret:", sharedSecret);

  // Derive AES key from shared secret using HMAC
  const aesKey = await HMACtoAESKey(sharedSecret, govEncryptionDataStr);

  // Decrypt the ciphertext using AES-GCM
  const plaintext = await decryptWithGCM(aesKey, ciphertext, header.iv);

  // Convert the ArrayBuffer (plaintext) back to a string
  return bufferToString(plaintext);
}

}

module.exports = {
  MessengerClient,
};
