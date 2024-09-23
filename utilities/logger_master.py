import logging
import functools
from logging.handlers import TimedRotatingFileHandler
import os
import datetime
import traceback


def log_function_entry_exit(logger):
    """
    Decorator to log the entry and exit of class methods.

    This decorator can be applied to a class to log the entry and exit of all its methods. It enhances the log
    messages with information about the method name, arguments, and keyword arguments.

    Args:
        logger (logging.Logger): The logger instance to use for logging.

    Returns:
        callable: A decorator function that can be applied to a class.
    """
    def decorator(cls):
        for name, func in cls.__dict__.items():
            if callable(func):
                setattr(cls, name, log_method_entry_exit(logger)(func))
        return cls
    return decorator


def log_method_entry_exit(logger):
    """
    Decorator to log the entry and exit of a method, including errors and tracebacks.

    This decorator can be applied to individual methods of a class to log the entry and exit of those methods.
    It enhances the log messages with information about the method name, arguments, and keyword arguments.
    Additionally, it captures and logs any exceptions that occur during method execution, along with traceback details.

    Args:
        logger (logging.Logger): The logger instance to use for logging.

    Returns:
        callable: A decorator function that can be applied to a method.
    """
    def decorator(method):
        @functools.wraps(method)
        def wrapper(*args, **kwargs):
            try:
                logger.info(f"Entering {method.__name__} with args: {args}, kwargs: {kwargs}")
                result = method(*args, **kwargs)
                logger.info(f"Exiting {method.__name__}")
                return result
            except Exception as e:
                logger.error(f"Error in {method.__name__}: {str(e)}")
                logger.error(traceback.format_exc())
                raise e
        return wrapper
    return decorator


def setup_logging(log_folder):
    """
    Set up logging configuration.

    This function configures the logging system by creating a logger instance, setting the log level to INFO, and
    creating a TimedRotatingFileHandler for date-based log rotation. It also creates a logs folder if it doesn't
    exist.

    Args:
        log_folder (str): The path to the folder where log files will be stored.

    Returns:
        logging.Logger: The configured logger instance.
    """
    # Create a logger instance
    logger = logging.getLogger(__name__)

    # Check if the logger already has handlers to avoid creating duplicate handlers
    if len(logger.handlers) > 0:
        return logger  # If handlers exist, return the logger to avoid duplicate handlers

    logger.setLevel(logging.INFO)

    # Get the current date in the format yyyy_mm_dd
    current_date = datetime.datetime.now().strftime("%Y_%m_%d")

    # Create a formatter
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

    # Create a TimedRotatingFileHandler for date-based log rotation
    log_file = os.path.join(log_folder, f'log_{current_date}.log')
    file_handler = TimedRotatingFileHandler(log_file, when='midnight', backupCount=7)  # Keep 7 days of logs
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    return logger


# Set up the logs folder
logs_folder = 'logs'
if not os.path.exists(logs_folder):
    os.makedirs(logs_folder)

# Configure logging
logger = setup_logging(logs_folder)
