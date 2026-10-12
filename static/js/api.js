/**
 * Shared API wrapper with comprehensive logging and error handling
 */

const API = {
    /**
     * Make an API call with full logging
     */
    async call(method, endpoint, data = null) {
        DEBUG.apiCall(method, endpoint, data);
        
        const options = {
            method: method.toUpperCase(),
            headers: {
                'Content-Type': 'application/json'
            }
        };
        
        if (data && (method.toUpperCase() === 'POST' || method.toUpperCase() === 'PUT')) {
            options.body = JSON.stringify(data);
            DEBUG.log(`API request body:`, data);
        }
        
        try {
            const response = await fetch(endpoint, options);
            DEBUG.apiResponse(method, endpoint, response.status);
            
            // Try to parse as JSON
            let responseData;
            try {
                responseData = await response.json();
                DEBUG.log(`API response data:`, responseData);
            } catch (e) {
                responseData = await response.text();
                DEBUG.warn(`API response was not JSON:`, responseData);
            }
            
            if (!response.ok) {
                DEBUG.error(`API error ${response.status}: ${endpoint}`, responseData);
                throw new Error(`API error: ${response.status}`);
            }
            
            return responseData;
        } catch (error) {
            DEBUG.error(`API call failed: ${method} ${endpoint}`, error);
            throw error;
        }
    },
    
    /**
     * GET request
     */
    async get(endpoint) {
        return this.call('GET', endpoint);
    },
    
    /**
     * POST request
     */
    async post(endpoint, data) {
        return this.call('POST', endpoint, data);
    },
    
    /**
     * PUT request
     */
    async put(endpoint, data) {
        return this.call('PUT', endpoint, data);
    },
    
    /**
     * DELETE request
     */
    async delete(endpoint) {
        return this.call('DELETE', endpoint);
    }
};

DEBUG.log('API module loaded');
