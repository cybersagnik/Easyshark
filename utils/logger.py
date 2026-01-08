"""
Logging configuration
"""
import logging
import sys
from pathlib import Path
from typing import Optional

def setup_logger(debug: bool = False, log_file: Optional[str] = None) -> logging.Logger:
    """Setup application logger"""
    level = logging.DEBUG if debug else logging.INFO
    
    log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    
    handlers = []
    
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(level)
        file_handler.setFormatter(logging.Formatter(log_format))
        handlers.append(file_handler)
    
    if debug:
        console_handler = logging.StreamHandler(sys.stderr)
        console_handler.setLevel(level)
        console_handler.setFormatter(logging.Formatter(log_format))
        handlers.append(console_handler)
    
    logging.basicConfig(
        level=level,
        format=log_format,
        handlers=handlers if handlers else [logging.NullHandler()]
    )
    
    logger = logging.getLogger('pcap_soc')
    logger.setLevel(level)
    
    return logger