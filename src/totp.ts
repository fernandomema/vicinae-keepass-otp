export interface TotpConfig {
  secret: string;
  period: number;
  digits: number;
  algorithm: "SHA1" | "SHA256" | "SHA512";
  issuer?: string;
  account?: string;
}

export interface OtpauthUri {
  type: "totp" | "hotp";
  label: string;
  config: TotpConfig;
}

function base32Decode(input: string): Uint8Array {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const clean = input.replace(/[\s=-]/g, "").toUpperCase();

  let bits = "";
  for (const char of clean) {
    const val = alphabet.indexOf(char);
    if (val === -1) continue;
    bits += val.toString(2).padStart(5, "0");
  }

  const bytes = new Uint8Array(Math.floor(bits.length / 8));
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(bits.slice(i * 8, i * 8 + 8), 2);
  }
  return bytes;
}

function toBuffer(data: Uint8Array): ArrayBuffer {
  const copy = new ArrayBuffer(data.byteLength);
  new Uint8Array(copy).set(data);
  return copy;
}

async function hmacSign(
  algorithm: "SHA-1" | "SHA-256" | "SHA-512",
  key: Uint8Array,
  message: Uint8Array
): Promise<Uint8Array> {
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    toBuffer(key),
    { name: "HMAC", hash: algorithm },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", cryptoKey, toBuffer(message));
  return new Uint8Array(sig);
}

function intToBytes(num: number): Uint8Array {
  const bytes = new Uint8Array(8);
  let temp = num;
  for (let i = 7; i >= 0; i--) {
    bytes[i] = temp & 0xff;
    temp = Math.floor(temp / 256);
  }
  return bytes;
}

function dynamicTruncation(hmac: Uint8Array): number {
  const offset = hmac[hmac.length - 1] & 0x0f;
  const binary =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);
  return binary;
}

function getHashAlgorithm(algo: TotpConfig["algorithm"]): "SHA-1" | "SHA-256" | "SHA-512" {
  switch (algo) {
    case "SHA256":
      return "SHA-256";
    case "SHA512":
      return "SHA-512";
    default:
      return "SHA-1";
  }
}

export async function generateTotp(config: TotpConfig, timestamp?: number): Promise<string> {
  const time = timestamp ?? Date.now();
  const counter = Math.floor(time / 1000 / config.period);
  const counterBytes = intToBytes(counter);
  const secretBytes = base32Decode(config.secret);

  const hmac = await hmacSign(getHashAlgorithm(config.algorithm), secretBytes, counterBytes);
  const otp = dynamicTruncation(hmac);
  const mod = Math.pow(10, config.digits);
  const code = (otp % mod).toString().padStart(config.digits, "0");
  return code;
}

export function getTimeRemaining(period: number = 30): number {
  const now = Math.floor(Date.now() / 1000);
  return period - (now % period);
}

export function parseOtpauthUri(uri: string): OtpauthUri | null {
  if (!uri.startsWith("otpauth://")) return null;

  const rest = uri.slice("otpauth://".length);
  const typeEnd = rest.indexOf("/");
  if (typeEnd === -1) return null;

  const type = rest.slice(0, typeEnd) as "totp" | "hotp";
  if (type !== "totp" && type !== "hotp") return null;

  const afterType = rest.slice(typeEnd + 1);
  const queryIdx = afterType.indexOf("?");
  const label = queryIdx >= 0 ? decodeURIComponent(afterType.slice(0, queryIdx)) : decodeURIComponent(afterType);
  const queryString = queryIdx >= 0 ? afterType.slice(queryIdx + 1) : "";

  const params = new URLSearchParams(queryString);
  const secret = params.get("secret");
  if (!secret) return null;

  const issuer = params.get("issuer") ?? undefined;
  const account = label.includes(":") ? label.split(":").slice(1).join(":") : undefined;

  return {
    type,
    label,
    config: {
      secret: secret.replace(/[\s=-]/g, "").toUpperCase(),
      period: parseInt(params.get("period") || "30", 10),
      digits: parseInt(params.get("digits") || "6", 10),
      algorithm: (params.get("algorithm")?.toUpperCase() as TotpConfig["algorithm"]) || "SHA1",
      issuer,
      account,
    },
  };
}
