/**
 * Visual Analysis Adapter Interface & Stub
 * Abstract contract for future computer vision, perceptual hashing, and screenshot similarity engines.
 * @module VisualAdapter
 */

export class VisualAdapter {
  /**
   * Compute perceptual hash (pHash) of an HTML Canvas or Image element.
   * @param {HTMLCanvasElement|HTMLImageElement} element 
   * @returns {Promise<string>} 64-bit hex hash string.
   */
  async computePerceptualHash(element) {
    if (!element) return '';
    // Placeholder contract stub for future OpenCV / pHash WASM integration
    return '0000000000000000';
  }

  /**
   * Compare visual similarity score between target screenshot and reference brand image.
   * @param {string} hashA 
   * @param {string} hashB 
   * @returns {number} Hamming distance similarity percentage (0.0 to 1.0).
   */
  compareHashes(hashA, hashB) {
    if (!hashA || !hashB || hashA.length !== hashB.length) return 0.0;
    let distance = 0;
    for (let i = 0; i < hashA.length; i++) {
      if (hashA[i] !== hashB[i]) distance++;
    }
    return 1.0 - (distance / hashA.length);
  }
}
