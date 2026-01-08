"""
Performance timing utilities
"""
import time
from functools import wraps
from typing import Callable
import logging

logger = logging.getLogger(__name__)

class Timer:
    def __init__(self, name: str = "Operation"):
        self.name = name
        self.start_time: float = 0.0
        self.end_time: float = 0.0
    
    def __enter__(self):
        self.start_time = time.time()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.end_time = time.time()
        elapsed = self.end_time - self.start_time
        logger.debug(f"{self.name} took {elapsed:.4f} seconds")
    
    def elapsed(self) -> float:
        """Get elapsed time"""
        if self.start_time and self.end_time:
            return self.end_time - self.start_time
        return 0.0

def timeit(func: Callable) -> Callable:
    """Decorator to time function execution"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        start = time.time()
        result = func(*args, **kwargs)
        end = time.time()
        logger.debug(f"{func.__name__} took {end - start:.4f} seconds")
        return result
    
    return wrapper

def benchmark(iterations: int = 100):
    """Decorator to benchmark function with multiple iterations"""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            times = []
            
            for _ in range(iterations):
                start = time.time()
                result = func(*args, **kwargs)
                end = time.time()
                times.append(end - start)
            
            avg_time = sum(times) / len(times)
            min_time = min(times)
            max_time = max(times)
            
            logger.info(f"{func.__name__} benchmark ({iterations} iterations):")
            logger.info(f"  Average: {avg_time:.6f}s")
            logger.info(f"  Min: {min_time:.6f}s")
            logger.info(f"  Max: {max_time:.6f}s")
            
            return result
        
        return wrapper
    
    return decorator