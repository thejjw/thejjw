const fs = require('node:fs')
const path = require('node:path')
const jsQR = require('jsqr')
const { PNG } = require('pngjs')

const root = __dirname

/** Normalize line endings because QR decoders may omit the final vCard newline. */
function normalizeVCard (value) {
  return value.replace(/\r?\n/g, '\n').trimEnd()
}

/** Decode one PNG and verify that its payload exactly matches the generated vCard. */
function verifyQr (filePath, expected) {
  const png = PNG.sync.read(fs.readFileSync(filePath))
  const result = jsQR(new Uint8ClampedArray(png.data), png.width, png.height)
  if (!result) throw new Error(`Could not decode ${path.basename(filePath)}`)
  if (normalizeVCard(result.data) !== normalizeVCard(expected)) {
    throw new Error(`Decoded content differs in ${path.basename(filePath)}`)
  }
  console.log(`Verified ${path.basename(filePath)} (${png.width}x${png.height})`)
}

/** Load the configured output names and verify both generated images. */
function main () {
  const contact = JSON.parse(fs.readFileSync(path.join(root, 'vcard.json'), 'utf8'))
  const baseName = contact.outputBaseName
  const expected = fs.readFileSync(path.join(root, `${baseName}.vcf`), 'utf8')
  verifyQr(path.join(root, `${baseName}.png`), expected)
  verifyQr(path.join(root, `${baseName}-signature.png`), expected)
}

try {
  main()
} catch (error) {
  console.error(error.message)
  process.exitCode = 1
}
