"""
Caching utilities for performance optimization
"""
from functools import wraps
from typing import Callable, Any
import hashlib
import pickle

class SimpleCache:
    def __init__(self, max_size: int = 1000):
        self.cache = {}
        self.max_size = max_size
    
    def get(self, key: str) -> Any:
        """Get cached value"""
        return self.cache.get(key)
    
    def set(self, key: str, value: Any):
        """Set cached value"""
        if len(self.cache) >= self.max_size:
            first_key = next(iter(self.cache))
            del self.cache[first_key]
        
        self.cache[key] = value
    
    def clear(self):
        """Clear all cache"""
        self.cache.clear()
    
    def has(self, key: str) -> bool:
        """Check if key exists"""
        return key in self.cache

def memoize(func: Callable) -> Callable:
    """Memoization decorator"""
    cache = {}
    
    @wraps(func)
    def wrapper(*args, **kwargs):
        key = str(args) + str(sorted(kwargs.items()))
        key_hash = hashlib.md5(key.encode()).hexdigest()
        
        if key_hash not in cache:
            cache[key_hash] = func(*args, **kwargs)
        
        return cache[key_hash]
    
    return wrapper

def cache_to_disk(filename: str):
    """Decorator to cache function results to disk"""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                with open(filename, 'rb') as f:
                    return pickle.load(f)
            except (FileNotFoundError, pickle.PickleError):
                result = func(*args, **kwargs)
                
                try:
                    with open(filename, 'wb') as f:
                        pickle.dump(result, f)
                except Exception:
                    pass
                
                return result
        
        return wrapper
    
    return decorator