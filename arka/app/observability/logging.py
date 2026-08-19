import logging
import structlog
from typing import Any

def setup_logging(log_level: str = "INFO") -> None:
    """Configure structured JSON logging.
    
    Args:
        log_level: The logging level to set.
    """
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=getattr(logging, log_level.upper(), logging.INFO),
    )
    
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.stdlib.add_log_level,
            structlog.stdlib.add_logger_name,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.processors.dict_tracebacks,
            structlog.processors.JSONRenderer(),
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

def get_logger(name: str, **kwargs: Any) -> structlog.stdlib.BoundLogger:
    """Get a bound logger with context.
    
    Args:
        name: The logger name.
        **kwargs: Initial bound context variables.
        
    Returns:
        A structlog bound logger instance.
    """
    return structlog.get_logger(name).bind(**kwargs)
