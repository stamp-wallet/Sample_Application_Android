# NTAG424DNA SDM Implementation with TapLinx SDK

This project implements Secure Dynamic Messaging (SDM) on NTAG424DNA tags using the NXP TapLinx SDK for Android. It configures tags to generate dynamic JSON or URL payloads containing the tag's UID, read counter, CMAC, business ID, and config ID. The application supports provisioning custom AES-128 keys and includes backend validation for CMAC.


## Overview
The application modifies the NXP TapLinx sample app to configure NTAG424DNA tags for SDM, enabling dynamic generation of:
- **JSON**: `{"uuid":"04112233445566","counter":"123","cmac":"A1B2C3D4E5F67890","businessId":1,"configId":1}`
- **URL**: `https://www.website.com/?uid=04112233445566&ctr=123&cmac=A1B2C3D4E5F67890&businessID=1&configID=1`

Key features:
- Authenticates with the default AES-128 key (`00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00`).
- Provisions a custom AES-128 key (e.g., `716e23615a627476754c5d682a4a7170`).
- Configures SDM on file `0x02` with `Encrypted` mode for CMAC generation.
- Logs UID, counter, and NDEF content for verification.
- Supports backend CMAC validation using Node.js.

## Prerequisites
- **Android Studio**: Version 4.0 or later.
- **NXP TapLinx SDK**: Version 1.8+ (includes `MFPCard.CommunicationMode.Encrypted` for CMAC).
- **NTAG424DNA Tags**: Factory-default tags with the default key (`00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00`).
- **Android Device**: NFC-capable, running Android 5.0+.
- **Node.js**: For CMAC validation on the backend (optional).

## Setup Instructions
1. **Clone the Repository**:
   ```bash
   git clone <repository-url>
   ```
2. **Open in Android Studio**:
   - Open Android Studio and select `Open an existing project`.
   - Navigate to the cloned repository folder and select it.
3. **Add TapLinx SDK**:
   - Download the TapLinx SDK v1.8+ from the [NXP website](https://www.nxp.com/support/developer-resources/software-tools/taplinx-sdk:NXP-TAPLINX-SDK).
   - Place `nxpnfcandroidlib-release.aar` in the `app/libs` directory.
   - Update `app/build.gradle`:
     ```gradle
     dependencies {
         implementation name: 'nxpnfcandroidlib-release', ext: 'aar'
         implementation 'androidx.appcompat:appcompat:1.6.1'
         implementation 'androidx.constraintlayout:constraintlayout:2.1.4'
     }
     ```
   - Sync the project.
4. **Configure Permissions**:
   - Ensure `AndroidManifest.xml` includes:
     ```xml
     <uses-permission android:name="android.permission.NFC" />
     <uses-feature android:name="android.hardware.nfc" android:required="true" />
     ```
5. **Build and Run**:
   - Connect an NFC-capable Android device via USB.
   - Build and run the app in Android Studio.

**Screenshot**: [Describe: Android Studio project open with `app/src/main/java/com/nxp/sampletaplinx/CardLogic.java` visible, showing the `tag424DNACardLogic` function.]

## Usage
1. **Launch the App**:
   - Open the app and navigate to the Write screen.
2. **Input Parameters**:
   - **New AES Key**: Enter a 32-character hexadecimal key (e.g., `716e23615a627476754c5d682a4a7170`) in `et_new_aes_key`. Leave blank to skip key change.
   - **Business ID**: Enter an integer (e.g., `1`) in `et_business_id`.
   - **Config ID**: Enter an integer (e.g., `1`) in `et_config_id`.
   - **JSON Toggle**: Check `cb_json_format` for JSON output or uncheck for URL.
3. **Tap the Tag**:
   - Hold a factory-default NTAG424DNA tag to the device’s NFC reader.
   - The app authenticates with the default key, provisions the new key (if provided), configures SDM, and writes the NDEF message.
4. **Verify Output**:
   - Check Logcat (filter by `Constants.TAG`) for:
     - "Authenticated with default key successfully"
     - "AES key provisioned on tag" (if key changed)
     - "SDM JSON NDEF written" or "SDM URL NDEF written"
     - "Read NDEF: {"uuid":"04112233445566","counter":"123","cmac":"A1B2C3D4E5F67890","businessId":1,"configId":1}"
     - "SDM Read Counter: 123"
   - Use an NFC reader app (e.g., NXP TagInfo) to read the tag’s NDEF message.

**Screenshot**: [Describe: Write screen with input fields filled (`et_new_aes_key`: `716e23615a627476754c5d682a4a7170`, `et_business_id`: `1`, `et_config_id`: `1`, `cb_json_format`: checked) and Logcat showing successful output.]

## CMAC Validation
The NTAG424DNA tag generates a CMAC (Cipher-based Message Authentication Code) during SDM reads, inserted into the NDEF message at the `sdmMacOffset` (configured as `0x49, 0x00, 0x00`). The CMAC is computed using the AES-128 key provisioned on the tag and validated on the backend using Node.js.

### Steps for CMAC Validation
1. **Retrieve NDEF Data**:
   - Read the tag’s NDEF message using an NFC reader or the app’s read functionality.
   - Extract `uuid`, `counter`, and `cmac` from the JSON (e.g., `{"uuid":"04112233445566","counter":"123","cmac":"A1B2C3D4E5F67890","businessId":1,"configId":1}`).
2. **Fetch the AES Key**:
   - Use the provisioned AES key (e.g., `716e23615a627476754c5d682a4a7170`) stored during the write operation.
   - In a production environment, store this key securely in a backend database, associated with the tag’s UID.
3. **Validate CMAC**:
   - Implement a Node.js backend to validate the CMAC using the `crypto` module, mimicking the `verifySecureDynamicMessagingMacWithAESMode` logic.
   - The CMAC is computed over the concatenated `UID` (7 bytes) and `counter` (3 bytes, big-endian).

### Node.js CMAC Validation Example
```javascript
const crypto = require('crypto');

// Inputs from NDEF message
const uid = Buffer.from('04112233445566', 'hex'); // 7 bytes
const counter = Buffer.from('000123', 'hex'); // 3 bytes, big-endian
const receivedCmac = Buffer.from('A1B2C3D4E5F67890', 'hex'); // 8 bytes
const aesKey = Buffer.from('716e23615a627476754c5d682a4a7170', 'hex'); // 16 bytes

// Compute CMAC
function computeCmac(uid, counter, key) {
  const cmac = crypto.createHmac('sha256', key)
                     .update(Buffer.concat([uid, counter]))
                     .digest()
                     .slice(0, 8); // Truncate to 8 bytes
  return cmac;
}

// Validate CMAC
const computedCmac = computeCmac(uid, counter, aesKey);
const isValid = computedCmac.equals(receivedCmac);
console.log('CMAC Valid:', isValid);
console.log('Computed CMAC:', computedCmac.toString('hex').toUpperCase());
```

**Notes**:
- The actual CMAC computation in `verifySecureDynamicMessagingMacWithAESMode` uses AES-CMAC (not SHA-256 HMAC). Replace `crypto.createHmac('sha256', key)` with an AES-CMAC library (e.g., `node-aes-cmac`).
- Install `node-aes-cmac`:
  ```bash
  npm install node-aes-cmac
  ```
- Updated example with AES-CMAC:
  ```javascript
  const { calculateCMAC } = require('node-aes-cmac');

  const uid = Buffer.from('04112233445566', 'hex');
  const counter = Buffer.from('000123', 'hex');
  const receivedCmac = Buffer.from('A1B2C3D4E5F67890', 'hex');
  const aesKey = Buffer.from('716e23615a627476754c5d682a4a7170', 'hex');

  const input = Buffer.concat([uid, counter]);
  const computedCmac = Buffer.from(calculateCMAC(input, aesKey), 'hex').slice(0, 8);
  const isValid = computedCmac.equals(receivedCmac);
  console.log('CMAC Valid:', isValid);
  console.log('Computed CMAC:', computedCmac.toString('hex').toUpperCase());
  ```

## Testing
1. **Prepare a Tag**:
   - Use a factory-default NTAG424DNA tag (default key: `00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00`).
2. **Write to Tag**:
   - Run the app, navigate to the Write screen.
   - Input:
     - New AES key: `716e23615a627476754c5d682a4a7170`
     - Business ID: `1`
     - Config ID: `1`
     - JSON toggle: Checked
   - Tap the tag.
   - Verify Logcat output:
     - "Authenticated with default key successfully"
     - "AES key provisioned on tag"
     - "SDM JSON NDEF written"
     - "Read NDEF: {"uuid":"04112233445566","counter":"123","cmac":"A1B2C3D4E5F67890","businessId":1,"configId":1}"
     - "SDM Read Counter: 123"
3. **Read and Validate**:
   - Use an NFC reader app to read the NDEF message.
   - Verify the `counter` increments on each tap (e.g., `124`, `125`).
   - Extract `uuid`, `counter`, and `cmac` and validate CMAC using the Node.js script above.
4. **Test URL Mode**:
   - Uncheck JSON toggle and repeat, verifying:
     - `https://www.website.com/?uid=04112233445566&ctr=123&cmac=A1B2C3D4E5F67890&businessID=1&configID=1`

**Screenshot**: [Describe: NFC reader app showing JSON output `{"uuid":"04112233445566","counter":"123","cmac":"A1B2C3D4E5F67890","businessId":1,"configId":1}`.]
