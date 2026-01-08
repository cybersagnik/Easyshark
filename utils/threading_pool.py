"""
Thread pool for parallel processing
"""
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, List, Any, Optional
import logging

logger = logging.getLogger(__name__)

class TaskPool:
    def __init__(self, max_workers: int = 4):
        self.max_workers = max_workers
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
    
    def map(self, func: Callable, items: List[Any], timeout: Optional[float] = None) -> List[Any]:
        """Map function over items in parallel"""
        results = []
        
        futures = [self.executor.submit(func, item) for item in items]
        
        for future in as_completed(futures, timeout=timeout):
            try:
                result = future.result()
                results.append(result)
            except Exception as e:
                logger.error(f"Task failed: {e}")
                results.append(None)
        
        return results
    
    def submit(self, func: Callable, *args, **kwargs):
        """Submit single task"""
        return self.executor.submit(func, *args, **kwargs)
    
    def shutdown(self, wait: bool = True):
        """Shutdown thread pool"""
        self.executor.shutdown(wait=wait)
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.shutdown()

def parallel_process(items: List[Any], func: Callable, max_workers: int = 4) -> List[Any]:
    """Process items in parallel using thread pool"""
    with TaskPool(max_workers=max_workers) as pool:
        return pool.map(func, items)