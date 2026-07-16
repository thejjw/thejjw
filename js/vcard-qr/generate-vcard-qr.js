const fs = require('node:fs/promises')
const path = require('node:path')
const QRCode = require('qrcode')

const root = __dirname
const configPath = path.join(root, 'vcard.json')

/** Escape characters that have special meaning in a vCard text value. */
function escapeVCardText (value) {
  return value.replace(/\\/g, '\\\\').replace(/,/g, '\\,').replace(/;/g, '\\;').replace(/\r?\n/g, '\\n')
}

/** Require a non-empty string so incomplete cards fail with a useful message. */
function requireText (value, field) {
  if (typeof value !== 'string' || value.trim() === '') {
    throw new Error(`vcard.json field "${field}" must be a non-empty string`)
  }
  return value.trim()
}

/** Convert the editable JSON contact record into a UTF-8 vCard 3.0 document. */
function buildVCard (contact) {
  const family = requireText(contact.name?.family, 'name.family')
  const given = requireText(contact.name?.given, 'name.given')
  const display = requireText(contact.name?.display, 'name.display')
  const lines = [
    'BEGIN:VCARD',
    'VERSION:3.0',
    `N:${escapeVCardText(family)};${escapeVCardText(given)};;;`,
    `FN:${escapeVCardText(display)}`,
    `ORG:${escapeVCardText(requireText(contact.company, 'company'))}`,
    `TITLE:${escapeVCardText(requireText(contact.title, 'title'))}`,
    `EMAIL;TYPE=INTERNET,WORK:${requireText(contact.email, 'email')}`,
    `TEL;TYPE=WORK,VOICE:${requireText(contact.officePhone, 'officePhone')}`,
    `TEL;TYPE=CELL,VOICE:${requireText(contact.mobilePhone, 'mobilePhone')}`,
    'END:VCARD'
  ]
  return `${lines.join('\r\n')}\r\n`
}

/** Generate the vCard plus master and signature-size QR PNG files. */
async function main () {
  const contact = JSON.parse(await fs.readFile(configPath, 'utf8'))
  const baseName = requireText(contact.outputBaseName, 'outputBaseName')
  const vCard = buildVCard(contact)
  const options = { errorCorrectionLevel: 'M', margin: 4 }

  await Promise.all([
    fs.writeFile(path.join(root, `${baseName}.vcf`), vCard, 'utf8'),
    QRCode.toFile(path.join(root, `${baseName}.png`), vCard, { ...options, width: 1200 }),
    QRCode.toFile(path.join(root, `${baseName}-signature.png`), vCard, { ...options, width: 300 })
  ])

  console.log(`Generated ${baseName}.vcf and two QR PNG files.`)
}

main().catch(error => {
  console.error(error.message)
  process.exitCode = 1
})
