"""Decorators for logging and error handling."""
import functools
import time
import logging
import json
from datetime import datetime

logger = logging.getLogger(__name__)

def log_execution(func):
    """Decorator to log function execution with timing."""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        func_name = func.__name__
        start_time = time.time()
        
        # Log entry
        logger.info(f"[ENTRY] {func_name} - args: {len(args)}, kwargs: {list(kwargs.keys())}")
        
        try:
            result = func(*args, **kwargs)
            elapsed = time.time() - start_time
            logger.info(f"[EXIT] {func_name} - completed in {elapsed:.3f}s")
            return result
        except Exception as e:
            elapsed = time.time() - start_time
            logger.error(f"[ERROR] {func_name} - failed after {elapsed:.3f}s: {str(e)}")
            raise
    
    return wrapper

def log_api_call(func):
    """Decorator to log API endpoint calls with request/response details."""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        from flask import request, g
        
        endpoint = func.__name__
        method = request.method
        path = request.path
        start_time = time.time()
        
        logger.info(f"[API_ENTRY] {method} {path} -> {endpoint}")
        if request.is_json and request.get_json():
            logger.debug(f"[API_REQUEST] Body: {json.dumps(request.get_json(), indent=2)}")
        
        try:
            result = func(*args, **kwargs)
            elapsed = time.time() - start_time
            
            # Log response
            if isinstance(result, tuple):
                response_data, status_code = result[0], result[1] if len(result) > 1 else 200
            else:
                response_data, status_code = result, 200
            
            logger.info(f"[API_EXIT] {method} {path} - {status_code} in {elapsed:.3f}s")
            if isinstance(response_data, dict):
                logger.debug(f"[API_RESPONSE] {json.dumps(response_data, indent=2)}")
            
            return result
        except Exception as e:
            elapsed = time.time() - start_time
            logger.error(f"[API_ERROR] {method} {path} - {str(e)} after {elapsed:.3f}s")
            raise
    
    return wrapper
