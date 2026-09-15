import os

# Auto-load .env file if present
_env_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), '.env')
if os.path.exists(_env_path):
    with open(_env_path, 'r', encoding='utf-8') as _f:
        for _line in _f:
            _line = _line.strip()
            if _line and not _line.startswith('#') and '=' in _line:
                _k, _v = _line.split('=', 1)
                _k = _k.strip()
                _v = _v.strip().strip("'\"")
                if _k and _v and _k not in os.environ:
                    os.environ[_k] = _v

class Config:
    """Base configuration for NetIntel NOC Platform."""
    SECRET_KEY = os.environ.get('SECRET_KEY', 'netintel-noc-secret-key')
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))
    UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
    MAX_CONTENT_LENGTH = 32 * 1024 * 1024  # 32 MB limit
    LOG_DIR = os.path.join(BASE_DIR, 'logs')
    UPLOAD_RETENTION_HOURS = 24


class DevelopmentConfig(Config):
    DEBUG = True
    ENV = 'development'


class ProductionConfig(Config):
    DEBUG = False
    ENV = 'production'


config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}

