# DSS Auth Coursework- 100164855

This coursework consists of two websites that are designed to work together in order to allow
the user to log in using 2 factor authentication.

## Requirements

Use the package manager [pip](https://pip.pypa.io/en/stable/) to install required packages.

```bash
pip install Flask
pip install flask_bcrypt
```

## Usage

From the root directory, in one terminal/cmd/powershell window.

```bash
cd .\AuthWebsite\
python .\app.py
```

Again from the root directory, in another terminal/cmd/powershell window.

```bash
cd .\TokenGenSite\
python .\app.py
```

Then, navigate to both: [https://127.0.0.1:5000](https://127.0.0.1:5000) and
[https://127.0.0.2:5000](https://127.0.0.2:5000) in separate browser tabs/windows.
---
**NOTE**

When navigating to these sites, due to the SSL/TLS certificates being self-signed most
browsers will flag this as a security issue. Ignore this and proceed to the site anyway.

---
