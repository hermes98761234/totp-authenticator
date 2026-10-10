import jsQR from 'jsqr'

/** Decodes a QR code from RGBA pixels; returns its text or null. */
export function decodeQrPixels(data: Uint8ClampedArray, width: number, height: number): string | null {
  return jsQR(data, width, height, { inversionAttempts: 'attemptBoth' })?.data ?? null
}

/** Decodes a QR code from an image File/Blob (downscales large images). */
export async function decodeQrFromImage(file: Blob): Promise<string | null> {
  const bmp = await createImageBitmap(file)
  for (const maxSide of [1600, 800, 400]) {
    const scale = Math.min(1, maxSide / Math.max(bmp.width, bmp.height))
    const c = document.createElement('canvas')
    c.width = Math.max(1, Math.round(bmp.width * scale))
    c.height = Math.max(1, Math.round(bmp.height * scale))
    const ctx = c.getContext('2d', { willReadFrequently: true })!
    ctx.drawImage(bmp, 0, 0, c.width, c.height)
    const img = ctx.getImageData(0, 0, c.width, c.height)
    const r = decodeQrPixels(img.data, c.width, c.height)
    if (r) return r
  }
  return null
}
