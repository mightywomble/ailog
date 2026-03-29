/**
 * Debug logging utility for the frontend
 * Provides console logging with timestamps, log levels, and function tracking
 */

const DEBUG = {
    // Log levels
    LEVELS: {
        DEBUG: 0,
        INFO: 1,
        WARN: 2,
        ERROR: 3
    },
    
    // Current log level (change this to filter output)
    currentLevel: 0,
    
    /**
     * Format timestamp for logging
     */
    getTimestamp() {
        const now = new Date();
        return now.toISOString().split('T')[1].split('Z')[0]; // HH:MM:SS.mmm
    },
    
    /**
     * Log a debug message
     */
    log(message, data = null) {
        if (this.currentLevel <= this.LEVELS.DEBUG) {
            const timestamp = this.getTimestamp();
            const prefix = `[${timestamp}] [DEBUG]`;
            console.log(`%c${prefix} ${message}`, 'color: #0066cc; font-weight: bold;', data || '');
        }
    },
    
    /**
     * Log info message
     */
    info(message, data = null) {
        if (this.currentLevel <= this.LEVELS.INFO) {
            const timestamp = this.getTimestamp();
            const prefix = `[${timestamp}] [INFO]`;
            console.info(`%c${prefix} ${message}`, 'color: #009900; font-weight: bold;', data || '');
        }
    },
    
    /**
     * Log warning message
     */
    warn(message, data = null) {
        if (this.currentLevel <= this.LEVELS.WARN) {
            const timestamp = this.getTimestamp();
            const prefix = `[${timestamp}] [WARN]`;
            console.warn(`%c${prefix} ${message}`, 'color: #ff9900; font-weight: bold;', data || '');
        }
    },
    
    /**
     * Log error message
     */
    error(message, data = null) {
        const timestamp = this.getTimestamp();
        const prefix = `[${timestamp}] [ERROR]`;
        console.error(`%c${prefix} ${message}`, 'color: #cc0000; font-weight: bold;', data || '');
    },
    
    /**
     * Log function entry
     */
    enter(functionName, args = {}) {
        this.log(`ENTER ${functionName}()`, args);
    },
    
    /**
     * Log function exit
     */
    exit(functionName, result = null) {
        if (result !== null && result !== undefined) {
            this.log(`EXIT ${functionName}()`, result);
        } else {
            this.log(`EXIT ${functionName}()`);
        }
    },
    
    /**
     * Log API call
     */
    apiCall(method, endpoint, data = null) {
        const timestamp = this.getTimestamp();
        console.log(
            `%c[${timestamp}] [API] ${method.toUpperCase()} ${endpoint}`,
            'color: #6600cc; font-weight: bold;',
            data || ''
        );
    },
    
    /**
     * Log API response
     */
    apiResponse(method, endpoint, status, data = null) {
        const timestamp = this.getTimestamp();
        const statusColor = status >= 200 && status < 300 ? '#009900' : '#cc0000';
        console.log(
            `%c[${timestamp}] [API_RESPONSE] ${method.toUpperCase()} ${endpoint} -> ${status}`,
            `color: ${statusColor}; font-weight: bold;`,
            data || ''
        );
    },
    
    /**
     * Create a wrapped function that logs entry/exit
     */
    wrap(func, functionName = null) {
        const name = functionName || func.name || 'anonymous';
        return function(...args) {
            DEBUG.enter(name, args);
            try {
                const result = func.apply(this, args);
                if (result instanceof Promise) {
                    return result
                        .then(r => {
                            DEBUG.exit(name, r);
                            return r;
                        })
                        .catch(e => {
                            DEBUG.error(`${name}() threw:`, e);
                            throw e;
                        });
                } else {
                    DEBUG.exit(name, result);
                    return result;
                }
            } catch (e) {
                DEBUG.error(`${name}() threw:`, e);
                throw e;
            }
        };
    }
};

// Export for module systems if needed
if (typeof module !== 'undefined' && module.exports) {
    module.exports = DEBUG;
}
