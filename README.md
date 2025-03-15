# Burp Suite Header Cleaner Extension

## 📌 Overview
The **Header Cleaner** extension for Burp Suite automatically removes unnecessary headers from HTTP requests, making them cleaner and more controlled. It also adds a custom Burp Suite tab (`Cleaned Headers`) to display the modified headers.

## 🔧 Features
✅ **Removes unnecessary headers** (e.g., `sec-fetch-site`, `accept-language`, `if-none-match`)  
✅ **Works in real-time** by modifying outgoing HTTP requests  
✅ **Adds a custom tab** in Burp Suite’s message editor to view cleaned headers  
✅ **Easy to install and use**  

## 📥 Installation
1. **Download the extension**  
   - Save the script as `HeaderCleaner.py` in a directory of your choice.

2. **Load the extension in Burp Suite**  
   - Open Burp Suite.
   - Navigate to **Extender > Extensions**.
   - Click **Add**.
   - Set **Extension Type** to `Python`.
   - Click **Select File** and choose `HeaderCleaner.py`.
   - Click **Next** and **Finish**.

3. **Confirm Installation**  
   - Go to **Extender > Extensions** and check if `Header Cleaner` is listed.
   - If you see **"Loaded successfully"**, the extension is working.

## 🛠️ How to Use
1. **Intercept and Modify Requests**  
   - Go to **Burp Proxy > Intercept** and capture a request.
   - The extension will automatically remove predefined headers.

2. **View Cleaned Headers**  
   - Open any HTTP request in **HTTP history** (under **Burp Proxy**).
   - A new tab named **"Cleaned Headers"** will appear.
   - This tab shows the modified request headers after removing unnecessary ones.

3. **Customization**  
   - If you want to **remove additional headers**, modify the `headers_to_remove` list in `HeaderCleaner.py` and reload the extension.

## 📄 Example: Before & After
### 🔴 Before Cleaning (Original Request)
```
GET /index.html HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0
Accept: text/html
Accept-Encoding: gzip, deflate
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Upgrade-Insecure-Requests: 1
```

### 🟢 After Cleaning (Processed Request)
```
GET /index.html HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0
```
✅ **Headers like `Accept-Encoding`, `Sec-Fetch-Site`, `Upgrade-Insecure-Requests` are removed!**  

## 🐞 Troubleshooting
- **Extension is not loading?**  
  - Ensure you have **Python installed** and correctly configured in Burp Suite.

- **Burp Suite is showing an error?**  
  - Check the **Burp Extender > Errors** tab for debugging.

- **Headers are not being removed?**  
  - Ensure the **intercepted request is outgoing** (this extension modifies only requests, not responses).
  - Modify the `headers_to_remove` list if needed.

## 💡 Notes
- This extension only modifies **outgoing HTTP requests** (not responses).
- It helps with **pentesting, bypassing WAFs, and debugging**.
- If you need more customization, modify the script and reload it.


