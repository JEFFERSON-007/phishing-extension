/**
 * Enterprise Logger Utility
 * Provides structured logging with level filtering and safe output handling.
 * @module Logger
 */

/**
 * Log Level enumeration.
 * @readonly
 * @enum {number}
 */
export const LogLevel = Object.freeze({
  DEBUG: 0,
  INFO: 1,
  WARN: 2,
  ERROR: 3,
  NONE: 4
});

export class Logger {
  /**
   * Create a scoped logger instance.
   * @param {string} scope - Context/module name for logging.
   * @param {number} [level=LogLevel.WARN] - Minimum log level to print.
   */
  constructor(scope = 'Core', level = LogLevel.WARN) {
    /** @type {string} */
    this.scope = scope;
    /** @type {number} */
    this.level = level;
  }

  /**
   * Set log level.
   * @param {number} level 
   */
  setLevel(level) {
    this.level = level;
  }

  /**
   * Format log message.
   * @private
   * @param {string} levelName 
   * @param {string} message 
   * @returns {string}
   */
  _format(levelName, message) {
    const timestamp = new Date().toISOString();
    return `[${timestamp}] [${levelName}] [${this.scope}]: ${message}`;
  }

  /**
   * Log debug message.
   * @param {string} message 
   * @param {...*} args 
   */
  debug(message, ...args) {
    if (this.level <= LogLevel.DEBUG) {
      // eslint-disable-next-line no-console
      console.debug(this._format('DEBUG', message), ...args);
    }
  }

  /**
   * Log info message.
   * @param {string} message 
   * @param {...*} args 
   */
  info(message, ...args) {
    if (this.level <= LogLevel.INFO) {
      // eslint-disable-next-line no-console
      console.info(this._format('INFO', message), ...args);
    }
  }

  /**
   * Log warning message.
   * @param {string} message 
   * @param {...*} args 
   */
  warn(message, ...args) {
    if (this.level <= LogLevel.WARN) {
      // eslint-disable-next-line no-console
      console.warn(this._format('WARN', message), ...args);
    }
  }

  /**
   * Log error message.
   * @param {string} message 
   * @param {...*} args 
   */
  error(message, ...args) {
    if (this.level <= LogLevel.ERROR) {
      // eslint-disable-next-line no-console
      console.error(this._format('ERROR', message), ...args);
    }
  }
}

export const defaultLogger = new Logger('System', LogLevel.WARN);
