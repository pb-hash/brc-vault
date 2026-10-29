// Decode a QR code from a PNG file. Usage: node test/qrdecode.mjs image.png
import { readFileSync } from 'node:fs';
import { PNG } from 'pngjs';
import jsQR from 'jsqr';

const png = PNG.sync.read(readFileSync(process.argv[2]));
const code = jsQR(new Uint8ClampedArray(png.data), png.width, png.height);
process.stdout.write(code ? code.data : '');
if (!code) process.exitCode = 1;
