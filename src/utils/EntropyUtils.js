/**
 * Entropy & String Metrics Utility
 * Mathematics engine for Shannon Entropy, Levenshtein Distance, and Keyboard Proximity.
 * @module EntropyUtils
 */

export class EntropyUtils {
  /**
   * Calculate Shannon Entropy of a string (bits per character).
   * High entropy (>4.2) often indicates randomly generated / DGA / obfuscated domains.
   * @param {string} str - Input string.
   * @returns {number} Entropy value between 0.0 and 8.0.
   */
  static calculateShannonEntropy(str) {
    if (!str || typeof str !== 'string' || str.length === 0) {
      return 0;
    }

    const frequencies = new Map();
    for (let i = 0; i < str.length; i++) {
      const char = str[i];
      frequencies.set(char, (frequencies.get(char) || 0) + 1);
    }

    let entropy = 0;
    const len = str.length;
    for (const count of frequencies.values()) {
      const p = count / len;
      entropy -= p * Math.log2(p);
    }

    return parseFloat(entropy.toFixed(4));
  }

  /**
   * Calculate Levenshtein Distance between two strings.
   * @param {string} strA - First string.
   * @param {string} strB - Second string.
   * @returns {number} Minimum edit operations (insertions, deletions, substitutions).
   */
  static calculateLevenshteinDistance(strA, strB) {
    if (strA === strB) return 0;
    if (!strA || !strA.length) return strB ? strB.length : 0;
    if (!strB || !strB.length) return strA.length;

    const lenA = strA.length;
    const lenB = strB.length;
    const matrix = Array.from({ length: lenA + 1 }, () => new Int32Array(lenB + 1));

    for (let i = 0; i <= lenA; i++) matrix[i][0] = i;
    for (let j = 0; j <= lenB; j++) matrix[0][j] = j;

    for (let i = 1; i <= lenA; i++) {
      for (let j = 1; j <= lenB; j++) {
        const cost = strA[i - 1] === strB[j - 1] ? 0 : 1;
        matrix[i][j] = Math.min(
          matrix[i - 1][j] + 1,       // Deletion
          matrix[i][j - 1] + 1,       // Insertion
          matrix[i - 1][j - 1] + cost // Substitution
        );
      }
    }

    return matrix[lenA][lenB];
  }

  /**
   * QWERTY Keyboard proximity lookup table.
   * @type {Record<string, string[]>}
   */
  static KEYBOARD_NEIGHBORS = Object.freeze({
    'q': ['w', 'a'], 'w': ['q', 'e', 's', 'a'], 'e': ['w', 'r', 'd', 's'],
    'r': ['e', 't', 'f', 'd'], 't': ['r', 'y', 'g', 'f'], 'y': ['t', 'u', 'h', 'g'],
    'u': ['y', 'i', 'j', 'h'], 'i': ['u', 'o', 'k', 'j'], 'o': ['i', 'p', 'l', 'k'],
    'p': ['o', 'l'], 'a': ['q', 'w', 's', 'z'], 's': ['a', 'w', 'e', 'd', 'z', 'x'],
    'd': ['s', 'e', 'r', 'f', 'x', 'c'], 'f': ['d', 'r', 't', 'g', 'c', 'v'],
    'g': ['f', 't', 'y', 'h', 'v', 'b'], 'h': ['g', 'y', 'u', 'j', 'b', 'n'],
    'j': ['h', 'u', 'i', 'k', 'n', 'm'], 'k': ['j', 'i', 'o', 'l', 'm'],
    'l': ['k', 'o', 'p'], 'z': ['a', 's', 'x'], 'x': ['z', 's', 'd', 'c'],
    'c': ['x', 'd', 'f', 'v'], 'v': ['c', 'f', 'g', 'b'], 'b': ['v', 'g', 'h', 'n'],
    'n': ['b', 'h', 'j', 'm'], 'm': ['n', 'j', 'k']
  });

  /**
   * Check if two characters are adjacent on a QWERTY keyboard.
   * @param {string} charA 
   * @param {string} charB 
   * @returns {boolean}
   */
  static isKeyboardAdjacent(charA, charB) {
    const a = charA.toLowerCase();
    const b = charB.toLowerCase();
    if (a === b) return true;
    const neighbors = EntropyUtils.KEYBOARD_NEIGHBORS[a];
    return neighbors ? neighbors.includes(b) : false;
  }
}
