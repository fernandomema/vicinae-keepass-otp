# KeePass OTP Viewer for Vicinae

Search and view OTP/TOTP codes from KeePass `.kdbx` databases directly from Vicinae.

## Features

- Read OTP entries from KeePass `.kdbx` databases (KDBX3 and KDBX4)
- Live TOTP code generation with countdown timer
- Supports all major OTP formats:
  - `otpauth://` URIs (KeePassXC, KeeWeb, KeePassium)
  - KeePass 2.x native `TimeOtp-Secret-Base32` fields
  - KeeTrayTotp `TOTP Seed` / `TOTP Settings` fields
- Search and filter entries by group
- Copy OTP codes to clipboard (concealed)
- Paste OTP codes directly into apps
- Real-time code refresh with visual expiry indicator

## Setup

1. Copy the extension to your Vicinae extensions directory:
   ```bash
   cp -r vicinae-keepass-otp ~/.config/vicinae/extensions/keepass-otp-viewer
   ```

2. Install dependencies:
   ```bash
   cd ~/.config/vicinae/extensions/keepass-otp-viewer
   npm install
   ```

3. Configure in Vicinae preferences:
   - Set the path to your `.kdbx` file
   - Enter your master password (or set a key file)

## Usage

Open Vicinae and search for "View OTP Codes" or "KeePass OTP". Select an entry and copy the code.

## Supported OTP Storage Formats

| Format | Fields |
|--------|--------|
| KeePassXC / KeeWeb | `otp` field with `otpauth://` URI |
| KeePass 2.x | `TimeOtp-Secret-Base32` |
| KeeTrayTotp | `TOTP Seed` + `TOTP Settings` |
| KeePass2Android | `otp` field or `TimeOtp-Secret-Base32` |

## License

MIT
