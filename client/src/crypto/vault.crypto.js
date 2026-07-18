// How many times we run the key derivation algorithm
// 100,000 iterations makes brute force attacks take years
const PBKDF2_ITERATIONS = 100000;
const KEY_LENGTH = 256; // 256-bit AES key

// STEP 1 — Derive an AES key from the master password
// This turns a human password into a cryptographic key
// The key NEVER leaves the browser
export async function deriveKey(masterPassword, salt) {
  // First import the master password as raw key material
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(masterPassword), // convert string to bytes
    "PBKDF2", // algorithm
    false, // not exportable — can never be extracted
    ["deriveKey"] // can only be used to derive other keys
  );

  // Now derive the actual AES-GCM encryption key
  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: new TextEncoder().encode(salt), // random salt per user
      iterations: PBKDF2_ITERATIONS, // 100k rounds = slow for attackers
      hash: "SHA-256",
    },
    keyMaterial,
    { name: "AES-GCM", length: KEY_LENGTH }, // output key type
    false, // not exportable — key cannot leave memory
    ["encrypt", "decrypt"] // what this key can do
  );
}

// STEP 2 — Encrypt data with AES-GCM
// Takes plaintext → returns encrypted string safe to send to server
export async function encrypt(plaintext, key) {
  // IV = Initialization Vector — random 12 bytes, unique per encryption
  // Never reuse an IV with the same key!
  const iv = crypto.getRandomValues(new Uint8Array(12));

  // Encrypt the data
  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv }, // algorithm + random iv
    key, // the derived key
    new TextEncoder().encode(plaintext) // convert string to bytes
  );

  // Combine iv + encrypted data so we can decrypt later
  // We need the iv to decrypt — but iv is NOT secret
  const combined = new Uint8Array(iv.byteLength + encrypted.byteLength);
  combined.set(iv, 0); // first 12 bytes = iv
  combined.set(new Uint8Array(encrypted), iv.byteLength); // rest = encrypted

  // Convert to base64 string so we can store/send it easily
  return btoa(String.fromCharCode(...combined));
}

// STEP 3 — Decrypt data
// Takes encrypted string → returns original plaintext
export async function decrypt(ciphertext, key) {
  // Convert base64 string back to bytes
  const combined = Uint8Array.from(atob(ciphertext), c => c.charCodeAt(0));

  // Split back into iv and encrypted data
  const iv = combined.slice(0, 12); // first 12 bytes = iv
  const data = combined.slice(12); // rest = encrypted data

  // Decrypt!
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv }, // same algorithm + same iv
    key, // same key
    data // the encrypted data
  );

  // Convert bytes back to string
  return new TextDecoder().decode(plaintext);
}

// STEP 4 — Generate a random salt for each user
// Salt makes sure two users with same password get different keys
export function generateSalt() {
  // 16 random bytes converted to hex string
  return Array.from(crypto.getRandomValues(new Uint8Array(16)))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}