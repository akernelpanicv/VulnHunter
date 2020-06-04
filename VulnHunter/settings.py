logger_config = {
    'version': 1,
    'disable_existing_loggers': False,

    'formatters': {
        'response_analyze_formatter': {
            'format': '[{levelname}]: {message}',
            'style': '{',
        },
    },
    'handlers': {
        'response_console': {
            'class': 'logging.StreamHandler',
            'level': 'INFO',
            'formatter': 'response_analyze_formatter',
        },
        'response_file': {
            'class': 'logging.FileHandler',
            'level': 'INFO',
            'filename': 'session.log',
            'mode': 'w',
            'formatter': 'response_analyze_formatter',
        },
    },
    'loggers': {
        'ResponseParser_logger': {
            'level': 'INFO',
            'handlers': ['response_console', 'response_file'],
        },
    },
}
