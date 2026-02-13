/**
 * TrustScope Cryptographic Signing (Ed25519)
 *
 * Key management and signing for attestations.
 * Keys stored at ~/.trustscope/keys/ed25519.{key,pub}
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync, chmodSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';
import * as ed from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha2.js';

// Configure ed25519 to use sha512
ed.hashes.sha512 = (...m: Uint8Array[]) => sha512(ed.etc.concatBytes(...m));

const KEYS_DIR = join(homedir(), '.trustscope', 'keys');
const PRIVATE_KEY_PATH = join(KEYS_DIR, 'ed25519.key');
const PUBLIC_KEY_PATH = join(KEYS_DIR, 'ed25519.pub');

export interface KeyPair {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
}

export interface SignedData {
  signature: string;  // Hex-encoded signature
  public_key: string; // Hex-encoded public key
}

/**
 * Ensure keys directory exists with proper permissions
 */
function ensureKeysDir(): void {
  if (!existsSync(KEYS_DIR)) {
    mkdirSync(KEYS_DIR, { recursive: true, mode: 0o700 });
  }
}

/**
 * Convert bytes to hex string
 */
function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Convert hex string to bytes
 */
function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}

/**
 * Generate a new Ed25519 key pair
 */
export function generateKeyPair(): KeyPair {
  const privateKey = ed.utils.randomSecretKey();
  const publicKey = ed.getPublicKey(privateKey);
  return { privateKey, publicKey };
}

/**
 * Save key pair to filesystem
 */
export function saveKeyPair(keyPair: KeyPair): void {
  ensureKeysDir();

  // Save private key (hex-encoded)
  writeFileSync(PRIVATE_KEY_PATH, bytesToHex(keyPair.privateKey), { mode: 0o600 });
  // Ensure permissions are correct (may be needed on some systems)
  chmodSync(PRIVATE_KEY_PATH, 0o600);

  // Save public key (hex-encoded)
  writeFileSync(PUBLIC_KEY_PATH, bytesToHex(keyPair.publicKey), { mode: 0o644 });
}

/**
 * Load key pair from filesystem
 */
export function loadKeyPair(): KeyPair | null {
  try {
    if (!existsSync(PRIVATE_KEY_PATH) || !existsSync(PUBLIC_KEY_PATH)) {
      return null;
    }

    const privateKeyHex = readFileSync(PRIVATE_KEY_PATH, 'utf-8').trim();
    const publicKeyHex = readFileSync(PUBLIC_KEY_PATH, 'utf-8').trim();

    return {
      privateKey: hexToBytes(privateKeyHex),
      publicKey: hexToBytes(publicKeyHex),
    };
  } catch {
    return null;
  }
}

/**
 * Get or generate key pair
 *
 * Loads existing key pair or generates a new one if none exists.
 */
export function getOrCreateKeyPair(): KeyPair {
  let keyPair = loadKeyPair();
  if (!keyPair) {
    keyPair = generateKeyPair();
    saveKeyPair(keyPair);
  }
  return keyPair;
}

/**
 * Check if signing keys exist
 */
export function hasSigningKeys(): boolean {
  return existsSync(PRIVATE_KEY_PATH) && existsSync(PUBLIC_KEY_PATH);
}

/**
 * Get public key only (for verification without private key)
 */
export function getPublicKey(): string | null {
  try {
    if (!existsSync(PUBLIC_KEY_PATH)) {
      return null;
    }
    return readFileSync(PUBLIC_KEY_PATH, 'utf-8').trim();
  } catch {
    return null;
  }
}

/**
 * Sign data with Ed25519
 *
 * @param data - Data to sign (will be JSON stringified if object)
 * @returns Signature and public key, or null if no keys
 */
export function sign(data: unknown): SignedData | null {
  const keyPair = loadKeyPair();
  if (!keyPair) {
    return null;
  }

  // Normalize data to bytes
  const dataStr = typeof data === 'string' ? data : JSON.stringify(data, null, 0);
  const dataBytes = new TextEncoder().encode(dataStr);

  // Sign using synchronous method
  const signature = ed.sign(dataBytes, keyPair.privateKey);

  return {
    signature: bytesToHex(signature),
    public_key: bytesToHex(keyPair.publicKey),
  };
}

/**
 * Verify a signature
 *
 * @param data - Original data that was signed
 * @param signature - Hex-encoded signature
 * @param publicKey - Hex-encoded public key
 * @returns true if valid, false otherwise
 */
export function verify(
  data: unknown,
  signature: string,
  publicKey: string,
): boolean {
  try {
    const dataStr = typeof data === 'string' ? data : JSON.stringify(data, null, 0);
    const dataBytes = new TextEncoder().encode(dataStr);

    const signatureBytes = hexToBytes(signature);
    const publicKeyBytes = hexToBytes(publicKey);

    return ed.verify(signatureBytes, dataBytes, publicKeyBytes);
  } catch {
    return false;
  }
}

/**
 * Sign attestation claims
 *
 * Creates a canonical JSON representation and signs it.
 */
export function signAttestation(claims: Record<string, unknown>): SignedData | null {
  // Create canonical JSON (sorted keys, no whitespace)
  const canonical = JSON.stringify(claims, Object.keys(claims).sort(), 0);
  return sign(canonical);
}

/**
 * Verify attestation signature
 */
export function verifyAttestation(
  claims: Record<string, unknown>,
  signature: string,
  publicKey: string,
): boolean {
  const canonical = JSON.stringify(claims, Object.keys(claims).sort(), 0);
  return verify(canonical, signature, publicKey);
}

/**
 * Rotate keys - generate new key pair
 *
 * WARNING: This invalidates all previous signatures.
 */
export function rotateKeys(): KeyPair {
  const keyPair = generateKeyPair();
  saveKeyPair(keyPair);
  return keyPair;
}

/**
 * Export public key in standard format
 */
export function exportPublicKey(): { algorithm: string; key: string } | null {
  const pubKey = getPublicKey();
  if (!pubKey) {
    return null;
  }
  return {
    algorithm: 'Ed25519',
    key: pubKey,
  };
}
