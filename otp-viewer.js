"use strict";
var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/otp-viewer.tsx
var otp_viewer_exports = {};
__export(otp_viewer_exports, {
  default: () => OtpViewer
});
module.exports = __toCommonJS(otp_viewer_exports);
var import_react = require("react");
var import_api = require("@vicinae/api");

// src/kdbx.ts
var kdbxweb = __toESM(require("kdbxweb"));

// src/totp.ts
function base32Decode(input) {
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
function toBuffer(data) {
  const copy = new ArrayBuffer(data.byteLength);
  new Uint8Array(copy).set(data);
  return copy;
}
async function hmacSign(algorithm, key, message) {
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
function intToBytes(num) {
  const bytes = new Uint8Array(8);
  let temp = num;
  for (let i = 7; i >= 0; i--) {
    bytes[i] = temp & 255;
    temp = Math.floor(temp / 256);
  }
  return bytes;
}
function dynamicTruncation(hmac) {
  const offset = hmac[hmac.length - 1] & 15;
  const binary = (hmac[offset] & 127) << 24 | (hmac[offset + 1] & 255) << 16 | (hmac[offset + 2] & 255) << 8 | hmac[offset + 3] & 255;
  return binary;
}
function getHashAlgorithm(algo) {
  switch (algo) {
    case "SHA256":
      return "SHA-256";
    case "SHA512":
      return "SHA-512";
    default:
      return "SHA-1";
  }
}
async function generateTotp(config, timestamp) {
  const time = timestamp ?? Date.now();
  const counter = Math.floor(time / 1e3 / config.period);
  const counterBytes = intToBytes(counter);
  const secretBytes = base32Decode(config.secret);
  const hmac = await hmacSign(getHashAlgorithm(config.algorithm), secretBytes, counterBytes);
  const otp = dynamicTruncation(hmac);
  const mod = Math.pow(10, config.digits);
  const code = (otp % mod).toString().padStart(config.digits, "0");
  return code;
}
function getTimeRemaining(period = 30) {
  const now = Math.floor(Date.now() / 1e3);
  return period - now % period;
}
function parseOtpauthUri(uri) {
  if (!uri.startsWith("otpauth://")) return null;
  const rest = uri.slice("otpauth://".length);
  const typeEnd = rest.indexOf("/");
  if (typeEnd === -1) return null;
  const type = rest.slice(0, typeEnd);
  if (type !== "totp" && type !== "hotp") return null;
  const afterType = rest.slice(typeEnd + 1);
  const queryIdx = afterType.indexOf("?");
  const label = queryIdx >= 0 ? decodeURIComponent(afterType.slice(0, queryIdx)) : decodeURIComponent(afterType);
  const queryString = queryIdx >= 0 ? afterType.slice(queryIdx + 1) : "";
  const params = new URLSearchParams(queryString);
  const secret = params.get("secret");
  if (!secret) return null;
  const issuer = params.get("issuer") ?? void 0;
  const account = label.includes(":") ? label.split(":").slice(1).join(":") : void 0;
  return {
    type,
    label,
    config: {
      secret: secret.replace(/[\s=-]/g, "").toUpperCase(),
      period: parseInt(params.get("period") || "30", 10),
      digits: parseInt(params.get("digits") || "6", 10),
      algorithm: params.get("algorithm")?.toUpperCase() || "SHA1",
      issuer,
      account
    }
  };
}

// src/kdbx.ts
function getFieldValue(entry, key) {
  const field = entry.fields.get(key);
  if (!field) return void 0;
  if (typeof field === "string") return field;
  return field.getText();
}
function entryHasOtp(entry) {
  if (getFieldValue(entry, "otp")) return true;
  if (getFieldValue(entry, "TimeOtp-Secret-Base32") || getFieldValue(entry, "TimeOtp-Secret")) return true;
  if (getFieldValue(entry, "TOTP Seed")) return true;
  return false;
}
function parseKeePass2Fields(entry) {
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
  let algorithm = "SHA1";
  if (algo.includes("SHA-256") || algo.includes("SHA256")) algorithm = "SHA256";
  else if (algo.includes("SHA-512") || algo.includes("SHA512")) algorithm = "SHA512";
  return { secret, period, digits, algorithm };
}
function parseKeeTrayTotpFields(entry) {
  const seed = getFieldValue(entry, "TOTP Seed");
  const settings = getFieldValue(entry, "TOTP Settings");
  if (!seed) return null;
  let period = 30;
  let digits = 6;
  const algorithm = "SHA1";
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
    algorithm
  };
}
function parseOtpField(value) {
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
      algorithm: "SHA1"
    };
  }
  return null;
}
function hexToBytes(hex) {
  const clean = hex.replace(/\s/g, "");
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}
function base64ToBytes(b64) {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}
var BASE32_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
function bytesToBase32(bytes) {
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
function extractOtpConfig(entry) {
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
function getGroupPath(group) {
  const parts = [];
  let current = group;
  while (current) {
    if (current.name) parts.unshift(current.name);
    current = current.parentGroup;
  }
  return parts.join(" / ");
}
async function readKdbxOtpEntries(fileData, password, keyFileData) {
  const credentials = new kdbxweb.KdbxCredentials(
    password ? kdbxweb.ProtectedValue.fromString(password) : null,
    keyFileData ? new Uint8Array(keyFileData) : void 0
  );
  const db = await kdbxweb.Kdbx.load(fileData, credentials);
  const entries = [];
  function traverse(group) {
    for (const entry of group.entries) {
      if (entryHasOtp(entry)) {
        const config = extractOtpConfig(entry);
        if (config) {
          entries.push({
            title: getFieldValue(entry, "Title") || "Untitled",
            username: getFieldValue(entry, "UserName") || "",
            group: getGroupPath(group),
            config,
            rawOtpUri: getFieldValue(entry, "otp")
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

// src/otp-viewer.tsx
var import_jsx_runtime = require("react/jsx-runtime");
function OtpViewer() {
  const [entries, setEntries] = (0, import_react.useState)([]);
  const [loading, setLoading] = (0, import_react.useState)(true);
  const [error, setError] = (0, import_react.useState)(null);
  const [timeLeft, setTimeLeft] = (0, import_react.useState)(getTimeRemaining());
  const [filter, setFilter] = (0, import_react.useState)("all");
  const preferences = (0, import_api.getPreferenceValues)();
  const refreshCodes = (0, import_react.useCallback)(async (otpEntries) => {
    const withCodes = [];
    for (const entry of otpEntries) {
      try {
        const code = await generateTotp(entry.config);
        withCodes.push({ ...entry, code });
      } catch {
      }
    }
    setEntries(withCodes);
  }, []);
  (0, import_react.useEffect)(() => {
    async function load() {
      try {
        if (!preferences["kdbx-file"]) {
          setError("No database file configured. Set the path in extension preferences.");
          setLoading(false);
          return;
        }
        const response = await fetch(preferences["kdbx-file"]);
        if (!response.ok) {
          throw new Error(`Failed to read file: ${response.statusText}`);
        }
        const fileData = await response.arrayBuffer();
        let keyFileData;
        if (preferences["key-file"]) {
          const keyResponse = await fetch(preferences["key-file"]);
          if (keyResponse.ok) {
            keyFileData = await keyResponse.arrayBuffer();
          }
        }
        const otpEntries = await readKdbxOtpEntries(
          fileData,
          preferences.password || "",
          keyFileData
        );
        await refreshCodes(otpEntries);
        setLoading(false);
      } catch (e) {
        setError(String(e));
        setLoading(false);
        await (0, import_api.showToast)({
          title: "Failed to load database",
          message: String(e),
          style: import_api.Toast.Style.Failure
        });
      }
    }
    load();
  }, [preferences["kdbx-file"], preferences.password, preferences["key-file"], refreshCodes]);
  (0, import_react.useEffect)(() => {
    if (entries.length === 0) return;
    const interval = setInterval(() => {
      setTimeLeft(getTimeRemaining());
      if (getTimeRemaining() === 30) {
        refreshCodes(entries);
      }
    }, 1e3);
    return () => clearInterval(interval);
  }, [entries, refreshCodes]);
  const groups = Array.from(new Set(entries.map((e) => e.group))).sort();
  const filtered = filter === "all" ? entries : entries.filter((e) => e.group === filter);
  if (loading) {
    return /* @__PURE__ */ (0, import_jsx_runtime.jsx)(import_api.List, { isLoading: true, children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)(import_api.List.EmptyView, { title: "Loading KeePass database..." }) });
  }
  if (error) {
    return /* @__PURE__ */ (0, import_jsx_runtime.jsx)(import_api.List, { children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)(
      import_api.List.EmptyView,
      {
        title: "Error",
        description: error,
        actions: /* @__PURE__ */ (0, import_jsx_runtime.jsx)(import_api.ActionPanel, { children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)(import_api.Action, { title: "Retry", onAction: () => window.location.reload() }) })
      }
    ) });
  }
  if (entries.length === 0) {
    return /* @__PURE__ */ (0, import_jsx_runtime.jsx)(import_api.List, { children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)(
      import_api.List.EmptyView,
      {
        title: "No OTP entries found",
        description: "No entries with OTP/TOTP configuration were found in this database."
      }
    ) });
  }
  return /* @__PURE__ */ (0, import_jsx_runtime.jsx)(
    import_api.List,
    {
      searchBarPlaceholder: "Search OTP entries...",
      isLoading: loading,
      searchBarAccessory: groups.length > 0 ? /* @__PURE__ */ (0, import_jsx_runtime.jsxs)(import_api.List.Dropdown, { tooltip: "Filter by group", value: filter, onChange: setFilter, children: [
        /* @__PURE__ */ (0, import_jsx_runtime.jsx)(import_api.List.Dropdown.Item, { title: "All Groups", value: "all" }),
        groups.map((g) => /* @__PURE__ */ (0, import_jsx_runtime.jsx)(import_api.List.Dropdown.Item, { title: g, value: g }, g))
      ] }) : void 0,
      children: filtered.map((entry) => /* @__PURE__ */ (0, import_jsx_runtime.jsx)(
        import_api.List.Item,
        {
          title: entry.title,
          subtitle: entry.username,
          icon: "\u{1F511}",
          accessories: [
            { text: entry.code },
            {
              tag: {
                value: `${timeLeft}s`,
                color: timeLeft <= 5 ? "red" : timeLeft <= 10 ? "orange" : "green"
              }
            }
          ],
          detail: /* @__PURE__ */ (0, import_jsx_runtime.jsx)(
            import_api.List.Item.Detail,
            {
              markdown: `# ${entry.title}

**OTP Code:** \`${entry.code}\`

**Time remaining:** ${timeLeft}s

---

**Group:** ${entry.group}

**Username:** ${entry.username}

**Algorithm:** ${entry.config.algorithm}

**Digits:** ${entry.config.digits}

**Period:** ${entry.config.period}s`
            }
          ),
          actions: /* @__PURE__ */ (0, import_jsx_runtime.jsxs)(import_api.ActionPanel, { children: [
            /* @__PURE__ */ (0, import_jsx_runtime.jsx)(import_api.Action.CopyToClipboard, { title: "Copy OTP Code", content: entry.code, concealed: true }),
            /* @__PURE__ */ (0, import_jsx_runtime.jsx)(import_api.Action.Paste, { title: "Paste OTP Code", content: entry.code }),
            /* @__PURE__ */ (0, import_jsx_runtime.jsx)(import_api.Action.CopyToClipboard, { title: "Copy Secret Key", content: entry.config.secret, concealed: true }),
            /* @__PURE__ */ (0, import_jsx_runtime.jsx)(import_api.Action, { title: "Refresh Codes", onAction: () => refreshCodes(entries) })
          ] })
        },
        `${entry.group}-${entry.title}`
      ))
    }
  );
}
