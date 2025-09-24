# NTAG424DNA SDM Implementation with TapLinx SDK

This project implements Secure Dynamic Messaging (SDM) on NTAG424DNA tags using the NXP TapLinx SDK for Android. It configures tags to generate dynamic JSON or URL payloads containing the tag's UID, read counter, CMAC, business ID, and config ID. The application supports provisioning custom AES-128 keys and includes backend validation for CMAC.


## Overview
The application modifies the NXP TapLinx sample app to configure NTAG424DNA tags for SDM, enabling dynamic generation of:
- **JSON**: `{"uuid":"04112233445566","counter":"123","cmac":"A1B2C3D4E5F67890","businessId":1,"configId":1, "reader":"NFC"}`
- **URL**: `https://www.website.com/?uid=04112233445566&ctr=123&cmac=A1B2C3D4E5F67890&businessID=1&configID=1`

Key features:
- Authenticates with the default AES-128 key (`00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00`).
- Provisions a custom AES-128 key (e.g., `716e23615a627476754c5d682a4a7170`).
- Configures SDM on file `0x02` with `Encrypted` mode for CMAC generation.
- Logs UID, counter, and NDEF content for verification.
- Supports backend CMAC validation using Node.js.

## Usage
1. **Launch the App**:
   - Open the app and navigate to the Write screen.
2. **Input Parameters**:
   - **New AES Key**: Enter a 32-character hexadecimal key (e.g., `716e23615a627476754c5d682a4a7170`).
   - **Business ID**: Enter an integer (e.g., `1`).
   - **Config ID**: Enter an integer (e.g., `1`).
   - **JSON Toggle**: Check for JSON output or uncheck for URL.
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

