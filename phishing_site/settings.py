"""
Django settings for phishing_site project.
"""

import os
import secrets
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

# SECRET_KEY — loaded from environment in production.
# For local development only, a fallback is generated at runtime (never reused across restarts).
SECRET_KEY = os.environ.get(
    "DJANGO_SECRET_KEY",
    secrets.token_urlsafe(50),  # safe fallback for local dev; set the env var in production
)

DEBUG = os.environ.get("DJANGO_DEBUG", "true").lower() == "true"

ALLOWED_HOSTS = os.environ.get("DJANGO_ALLOWED_HOSTS", "127.0.0.1,localhost").split(",")

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'web',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'phishing_site.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'phishing_site.wsgi.application'

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}

AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator'},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]

LANGUAGE_CODE = 'ar'
TIME_ZONE = 'Asia/Riyadh'
USE_I18N = True
USE_TZ = True

STATIC_URL = 'static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'
STATICFILES_STORAGE = 'whitenoise.storage.CompressedManifestStaticFilesStorage'
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# Sessions expire after 24 hours
SESSION_COOKIE_AGE = 86400

# ---------------------------------------------------------------------------
# Logging — writes to logs/app.log with daily rotation (keeps 30 days)
# Format: 2026-03-31 14:22:01 | ERROR | web.views | Scan failed for URL: ...
# ---------------------------------------------------------------------------
LOGS_DIR = BASE_DIR / "logs"
LOGS_DIR.mkdir(exist_ok=True)

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,

    "formatters": {
        "detailed": {
            "format": "{asctime} | {levelname:<8} | {name} | {message}",
            "style": "{",
            "datefmt": "%Y-%m-%d %H:%M:%S",
        },
        "simple": {
            "format": "{levelname} {message}",
            "style": "{",
        },
    },

    "handlers": {
        # Rotating file — new file each day, keep 30 days of history
        "file": {
            "class": "logging.handlers.TimedRotatingFileHandler",
            "filename": LOGS_DIR / "app.log",
            "when": "midnight",
            "backupCount": 30,
            "encoding": "utf-8",
            "formatter": "detailed",
            "level": "DEBUG",
        },
        # Console — show INFO+ during development
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "simple",
            "level": "INFO",
        },
    },

    "loggers": {
        # Our app code
        "web": {
            "handlers": ["file", "console"],
            "level": "DEBUG",
            "propagate": False,
        },
        "detector": {
            "handlers": ["file", "console"],
            "level": "DEBUG",
            "propagate": False,
        },
        # Django internals — only warnings and above go to file
        "django": {
            "handlers": ["file", "console"],
            "level": "WARNING",
            "propagate": False,
        },
        "django.request": {
            "handlers": ["file", "console"],
            "level": "ERROR",
            "propagate": False,
        },
        # Silence noisy third-party libraries
        "urllib3": {"handlers": [], "level": "WARNING", "propagate": False},
        "charset_normalizer": {"handlers": [], "level": "WARNING", "propagate": False},
    },
}
