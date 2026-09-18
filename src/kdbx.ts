import * as kdbxweb from "kdbxweb";
import argon2 from "argon2";
import { TotpConfig, parseOtpauthUri } from "./totp";

export interface OtpEntry {
  title: string;
  username: string;
  group: string;
  config: TotpConfig;
  rawOtpUri?: string;
}

function getFieldValue(entry: kdbxweb.KdbxEntry, key: string): string | undefined {
  const field = entry.fields.get(key);
  if (!field) return undefined;
  if (typeof field === "string") return field;
  return field.getText();
}

function entryHasOtp(entry: kdbxweb.KdbxEntry): boolean {
  if (getFieldValue(entry, "otp")) return true;
  if (getFieldValue(entry, "TimeOtp-Secret-Base32") || getFieldValue(entry, "TimeOtp-Secret")) return true;
  if (getFieldValue(entry, "TOTP Seed")) return true;
  return false;
}

function parseKeePass2Fields(entry: kdbxweb.KdbxEntry): TotpConfig | null {
  const secret32 = getFieldValue(entry, "TimeOtp-Secret-Base32");
  const secretHex = getFieldValue(entry, "TimeOtp-Secret-Hex");
  const secretBase64 = getFieldValue(entry, "TimeOtp-Secret-Base64");

  let secret = "";
  if (secret32) {
    secret = secret32.replace(/[\s=-]/g, "").toUpperCase();
  } else if (secretHex) {
    const bytes = hexToBytes(secretHex);
    secret = bytesToBase32(bytes);
  } else if (secretBase64) {
    const bytes = base64ToBytes(secretBase64);
    secret = bytesToBase32(bytes);
  } else {
    return null;
  }

  const periodStr = getFieldValue(entry, "TimeOtp-Length");
  const period = periodStr ? parseInt(periodStr, 10) : 30;
  const digitsStr = getFieldValue(entry, "TimeOtp-Digits");
  const digits = digitsStr ? parseInt(digitsStr, 10) : 6;
  const algo = getFieldValue(entry, "TimeOtp-Algorithm")?.toUpperCase() || "HMAC-SHA-1";

  let algorithm: TotpConfig["algorithm"] = "SHA1";
  if (algo.includes("SHA-256") || algo.includes("SHA256")) algorithm = "SHA256";
  else if (algo.includes("SHA-512") || algo.includes("SHA512")) algorithm = "SHA512";

  return { secret, period, digits, algorithm };
}

function parseKeeTrayTotpFields(entry: kdbxweb.KdbxEntry): TotpConfig | null {
  const seed = getFieldValue(entry, "TOTP Seed");
  const settings = getFieldValue(entry, "TOTP Settings");
  if (!seed) return null;

  let period = 30;
  let digits = 6;
  const algorithm: TotpConfig["algorithm"] = "SHA1";

  if (settings) {
    const parts = settings.split(";");
    if (parts.length >= 1) period = parseInt(parts[0], 10) || 30;
    if (parts.length >= 2) {
      const d = parts[1];
      if (d === "S") {
        digits = 5;
      } else {
        digits = parseInt(d, 10) || 6;
      }
    }
  }

  return {
    secret: seed.replace(/[\s=-]/g, "").toUpperCase(),
    period,
    digits,
    algorithm,
  };
}

function parseOtpField(value: string): TotpConfig | null {
  const trimmed = value.trim();
  if (trimmed.startsWith("otpauth://")) {
    const parsed = parseOtpauthUri(trimmed);
    return parsed?.config ?? null;
  }
  if (/^[A-Z2-7\s=]+$/i.test(trimmed)) {
    return {
      secret: trimmed.replace(/[\s=-]/g, "").toUpperCase(),
      period: 30,
      digits: 6,
      algorithm: "SHA1",
    };
  }
  return null;
}

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.replace(/\s/g, "");
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function base64ToBytes(b64: string): Uint8Array {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

const BASE32_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function bytesToBase32(bytes: Uint8Array): string {
  let bits = "";
  for (const b of bytes) {
    bits += b.toString(2).padStart(8, "0");
  }
  let result = "";
  for (let i = 0; i < bits.length; i += 5) {
    const chunk = bits.slice(i, i + 5).padEnd(5, "0");
    result += BASE32_CHARS[parseInt(chunk, 2)];
  }
  return result;
}

export function extractOtpConfig(entry: kdbxweb.KdbxEntry): TotpConfig | null {
  const otpField = getFieldValue(entry, "otp");
  if (otpField) {
    const config = parseOtpField(otpField);
    if (config) return config;
  }

  const kp2Config = parseKeePass2Fields(entry);
  if (kp2Config) return kp2Config;

  const trayConfig = parseKeeTrayTotpFields(entry);
  return trayConfig;
}

function getGroupPath(group: kdbxweb.KdbxGroup): string {
  const parts: string[] = [];
  let current: kdbxweb.KdbxGroup | undefined = group;
  while (current) {
    if (current.name) parts.unshift(current.name);
    current = current.parentGroup;
  }
  return parts.join(" /");
}

let argon2Registered = false;

function ensureArgon2() {
  if (argon2Registered) return;
  argon2Registered = true;

  kdbxweb.CryptoEngine.setArgon2Impl(
    async (password, salt, memory, iterations, length, parallelism, type, version) => {
      const passBuf = Buffer.from(password);
      const saltBuf = Buffer.from(salt);

      let hash: Buffer;
      if (type === 1) {
        hash = await argon2.hash(passBuf, {
          type: argon2.argon2i,
          memoryCost: memory,
          timeCost: iterations,
          parallelism,
          salt: saltBuf,
          hashLength: length,
          raw: true,
        });
      } else if (type === 0) {
        hash = await argon2.hash(passBuf, {
          type: argon2.argon2d,
          memoryCost: memory,
          timeCost: iterations,
          parallelism,
          salt: saltBuf,
          hashLength: length,
          raw: true,
        });
      } else {
        hash = await argon2.hash(passBuf, {
          type: argon2.argon2id,
          memoryCost: memory,
          timeCost: iterations,
          parallelism,
          salt: saltBuf,
          hashLength: length,
          raw: true,
        });
      }

      return hash.buffer.slice(hash.byteOffset, hash.byteOffset + hash.byteLength);
    }
  );
}

export async function readKdbxOtpEntries(
  fileData: ArrayBuffer,
  password: string,
  keyFileData?: ArrayBuffer
): Promise<OtpEntry[]> {
  ensureArgon2();

  const credentials = new kdbxweb.KdbxCredentials(
    password ? kdbxweb.ProtectedValue.fromString(password) : null,
    keyFileData ? new Uint8Array(keyFileData) : undefined
  );

  const db = await kdbxweb.Kdbx.load(fileData, credentials);
  const entries: OtpEntry[] = [];

  function traverse(group: kdbxweb.KdbxGroup) {
    for (const entry of group.entries) {
      if (entryHasOtp(entry)) {
        const config = extractOtpConfig(entry);
        if (config) {
          entries.push({
            title: getFieldValue(entry, "Title") || "Untitled",
            username: getFieldValue(entry, "UserName") || "",
            group: getGroupPath(group),
            config,
            rawOtpUri: getFieldValue(entry, "otp"),
          });
        }
      }
    }
    for (const child of group.groups) {
      traverse(child);
    }
  }

  const defaultGroup = db.getDefaultGroup();
  traverse(defaultGroup);
  return entries;
}
