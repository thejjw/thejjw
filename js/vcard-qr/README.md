# Bilingual vCard QR generator

Edit `vcard.json`, then run:

```powershell
npm install
npm run generate
npm test
```

The generator creates a UTF-8 vCard 3.0 file, a 1200 px master PNG, and a
300 px email-signature PNG. The test decodes both images and compares their
contents with the generated vCard.

Use the signature PNG in email and display it at roughly 120-150 px wide.
Always send yourself a test message and scan the received image before rollout.
