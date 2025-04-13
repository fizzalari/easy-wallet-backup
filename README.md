## Description

`easy-wallet-backup` is a tool designed to extract private keys from a `wallet.dat` (descriptor) file and export them in an Electrum-compatible format. This project is fully developed in Python.

## **Features**
1. **Dump Descriptor**:
   - Load a `wallet.dat` file and extract the descriptors along with their private keys.
   
2. **Extended PrivKey (xpriv)**:
   - Generate a series of addresses derived directly from the `xpriv`, without requiring the `wallet.dat` file.

3. **Extract Addresses**:
   - List all the wallet addresses contained in the `wallet.dat` .

---

bitcointalk thread: https://bitcointalk.org/index.php?topic=5538029

## **Prerequisites**
1. Install **Bitcoin Core**:
   - Required only to extract the descriptors from your wallet.
   - You **do not need to download the blockchain**.
   - Always work with a **backup of your wallet.dat file** to avoid potential loss or corruption.
2. Install the required Python dependencies:
   - Make sure you have Python installed on your system.
   - Run the following command to install the necessary dependencies:
     ```bash
     pip install -r requirements.txt
     ```

---

## **How to Use**

### Step 1: Extracting the Descriptors
1. Open **Bitcoin Core**.
2. Load your wallet (if not already loaded).
3. Open the console:
   - Use **Window -> Console** or press `Ctrl+T`.
4. Execute the following command:
   ```bash
   listdescriptors true
   ```
5. Copy the **master private key** (commonly referred to as `xpriv`).

---

### Step 2: Using `easy_wallet_backup.py`
1. Open the `easy_wallet_backup.py` script.
2. Load your `wallet.dat` file.
3. Select **Dump Descriptor** and paste the `xpriv` key in the appropriate line.
4. Click the **Go** button:
   - This will list the addresses and corresponding private keys present in the `wallet.dat` file.

---

### Step 3: Exporting to Electrum-Compatible Format
- For Electrum-compatible addresses:
  1. Click the **Export2Electrum** button.
  2. Save the result using the **Save Result** button, or copy the list to import into Electrum via the **Import Private Keys** option.

**Note**: Addresses not supported by Electrum (e.g., Taproot addresses) will be omitted.

---

## **Alternative Options**
1. **Using the Extended Private Key (`xpriv`)**:
   - Generate a series of addresses derived from the `xpriv`.
   - The `wallet.dat` file is not necessary, as these addresses follow standard hierarchical derivations.

2. **Listing Addresses in `wallet.dat`**:
   - Simply load the `wallet.dat` file and list the available addresses and keys without exporting.

---
