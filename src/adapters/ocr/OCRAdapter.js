/**
 * OCR Adapter Interface & Stub
 * Abstract contract for future optical character recognition engines (Tesseract.js, EasyOCR, local WASM).
 * @module OCRAdapter
 */

export class OCRAdapter {
  /**
   * Extract text from image / canvas payload.
   * @param {ImageData|HTMLCanvasElement|string} source - Image source payload.
   * @returns {Promise<{ text: string, confidence: number, words: Array<{ text: string, bbox: number[] }> }>}
   */
  async extractText(source) {
    if (!source) {
      return { text: '', confidence: 0.0, words: [] };
    }

    // Placeholder interface stub
    return {
      text: '',
      confidence: 0.0,
      words: []
    };
  }
}
