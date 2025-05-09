# Django settings for munkiwebadmin project.
import os
import socket

try:
    HOSTNAME = socket.gethostname()
except:
    HOSTNAME = 'localhost'

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATIC_URL = '/static/'
MEDIA_URL = "/media/"

###########################################################################
# munkiwebadmin-specific
###########################################################################
# APPNAME is user-visible web app name
APPNAME = os.getenv('APPNAME', 'MunkiWebAdmin')
DEFAULT_MANIFEST = os.getenv('DEFAULT_MANIFEST', 'serial_number')
SECRET_KEY = os.environ.get("SECRET_KEY", "CHANGEME!!!")
ALLOWED_HOSTS = os.environ.get("ALLOWED_HOSTS", "localhost 127.0.0.1 [::1]").split(" ")
CSRF_TRUSTED_ORIGINS = os.environ.get("CSRF_TRUSTED_ORIGINS", "http://localhost").split(" ")
CSRF_COOKIE_SECURE = False  # Set to True if using HTTPS
CSRF_COOKIE_HTTPONLY = False

# Munki repo settings
MUNKI_REPO_URL = os.getenv('MUNKI_REPO_URL', 'file:///munkirepo')
if MUNKI_REPO_URL.startswith('file://'):
    if not os.path.exists(MUNKI_REPO_URL[7:]):
        MUNKI_REPO_URL = os.path.join('file:///' + BASE_DIR, 'munkirepo')

MUNKI_REPO_PLUGIN = os.getenv('MUNKI_REPO_PLUGIN', 'FileRepo')
MUNKITOOLS_DIR = os.getenv('MUNKITOOLS_DIR', '/munkitools')
if not os.path.exists(MUNKITOOLS_DIR):
    MUNKITOOLS_DIR = os.path.join(BASE_DIR, 'munkitools')

# Azure AD settings
CLIENT_ID = os.getenv('CLIENT_ID', 'ID')
CLIENT_SECRET = os.getenv('CLIENT_SECRET', None)
TENANT_ID = os.getenv('TENANT_ID', None)
ENTRA_ONLY = os.getenv('ENTRA_ONLY', 'False').lower() in ('true', '1', 't')
EXCLUDE_API = os.getenv('EXCLUDE_API', False)
SECURE_SSL_REDIRECT = os.getenv('SECURE_SSL_REDIRECT', False)

if SECURE_SSL_REDIRECT:
    SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')

# Azure App Service
if os.environ.get('WEBSITE_HOSTNAME'):
    ALLOWED_HOSTS.append(os.environ.get('WEBSITE_HOSTNAME'))
    CSRF_TRUSTED_ORIGINS.append("https://" + os.environ.get('WEBSITE_HOSTNAME'))

# debug mode
DEBUG = os.getenv("DEBUG", 'False').lower() in ('true', '1', 't')

# package display settings
ENABLE_REPO_VIEW = os.getenv('ENABLE_REPO_VIEW', 'False').lower() in ('true', '1', 't')
CATALOGS_TO_DISPLAY = os.getenv('CATALOGS_TO_DISPLAY', '[]').split()
SHOW_ICONS = os.getenv('SHOW_ICONS', 'False').lower() in ('true', '1', 't')

# CORS settings
CORS_ORIGIN_ALLOW_ALL = DEBUG
CORS_ORIGIN_WHITELIST = ()
LOGIN_EXEMPT_URLS = ()

# django ldap auth
USE_LDAP = False

# Active Users
SESSION_COOKIE_AGE = 3600  # 1 hour
SESSION_EXPIRE_AT_BROWSER_CLOSE = True
SESSION_SAVE_EVERY_REQUEST = True
SESSION_ENGINE = 'django.contrib.sessions.backends.db'

###########################################################################
# munkiwebadmin-specific end
###########################################################################

# Application definition
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'corsheaders',
    'rest_framework',
    'django_auth_adfs',

    # our apps
    'api',
    'catalogs',
    'pkgsinfo',
    'manifests',
    'process',
    'icons',
    'santa',
    'munkiwebadmin',
    'monitoring',
    'vulnerabilities'
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'django_auth_adfs.middleware.LoginRequiredMiddleware',
]

ROOT_URLCONF = 'munkiwebadmin.urls'
TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [ os.path.join(BASE_DIR, 'munkiwebadmin/templates') ],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
                "munkiwebadmin.processor.index",
            ],
            'debug': DEBUG,
        },
    },
]

WSGI_APPLICATION = 'munkiwebadmin.wsgi.application'

""" if os.getenv('AZURE_DB_STRING'):
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.postgresql',
            'NAME': ,
            'USER': ,
            'PASSWORD': ,
            'HOST': ,
            'PORT': ,
        }
    }
el """
if os.getenv('DB') == 'postgres':
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.postgresql',
            'NAME': os.getenv('DB_NAME'),
            'USER': os.getenv('DB_USER'),
            'PASSWORD': os.getenv('DB_PASS'),
            'HOST': os.getenv('DB_HOST'),
            'PORT': os.getenv('DB_PORT'),
        }
    }
elif os.getenv('DB') == 'mysql':
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.mysql',
            'NAME': os.getenv('DB_NAME'),
            'USER': os.getenv('DB_USER'),
            'PASSWORD': os.getenv('DB_PASS'),
            'HOST': os.getenv('DB_HOST'),
            'PORT': os.getenv('DB_PORT'),
        }
    }
else:
    DATABASES = {
        "default": {
            "ENGINE": os.environ.get("SQL_ENGINE", "django.db.backends.sqlite3"),
            "NAME": os.environ.get("SQL_DATABASE", os.path.join(BASE_DIR, "db.sqlite3")),
            "USER": os.environ.get("SQL_USER", "user"),
            "PASSWORD": os.environ.get("SQL_PASSWORD", "password"),
            "HOST": os.environ.get("SQL_HOST", "localhost"),
            "PORT": os.environ.get("SQL_PORT", "5432"),
        }
    }

AUTH_PASSWORD_VALIDATORS = [ {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

# Internationalization
# https://docs.djangoproject.com/en/1.9/topics/i18n/
LANGUAGE_CODE = os.getenv('LANGUAGE_CODE', 'en-us')
TIME_ZONE = os.getenv('TIME_ZONE', 'UTC')
USE_I18N = True
USE_L10N = True
USE_TZ = True


LOGLEVEL = 'WARNING'

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '%(levelname)s %(asctime)s %(module)s %(process)d %(thread)d %(message)s'
        },
        'simple': {
            'format': '%(levelname)s %(message)s'
        },
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'simple'
        },
        'file': {
            'class':'logging.handlers.RotatingFileHandler',
            'filename': 'munkiwebadmin.log',
            'maxBytes': 1024*1024*5, # 5 MB
            'backupCount': 5,
            'formatter': 'verbose'
        },
    },
    'loggers': {
        'django': {
            'handlers': ['console', 'file'],
            'level': LOGLEVEL,
            'propagate': False
        },
        'munkiwebadmin': {
            'level': LOGLEVEL,
            'handlers': ['console', 'file'],
            'propagate': False,
        },
        'django_auth_adfs': {
            'handlers': ['console'],
            'level': LOGLEVEL,
        },
    },
}

CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
    }
}


STATICFILES_STORAGE = 'whitenoise.storage.CompressedStaticFilesStorage'
STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')
# Additional locations of static files
STATICFILES_DIRS = (
    # Put strings here, like "/home/html/static" or "C:/www/django/static".
    # Always use forward slashes, even on Windows.
    # Don't forget to use absolute paths, not relative paths.
    os.path.join(BASE_DIR, 'munkiwebadmin/static'),
)

# List of finder classes that know how to find static files in
# various locations.
STATICFILES_FINDERS = (
    'django.contrib.staticfiles.finders.FileSystemFinder',
    'django.contrib.staticfiles.finders.AppDirectoriesFinder',
)

# rest framework settings
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'django_auth_adfs.rest_framework.AdfsAccessTokenAuthentication',
        'rest_framework.authentication.BasicAuthentication',
        'rest_framework.authentication.SessionAuthentication',
    )
}

# azure adfs settings
LOGIN_EXCLUDE_URLS = []
if EXCLUDE_API:
    LOGIN_EXCLUDE_URLS.append('^api',)

if ENABLE_REPO_VIEW:
    LOGIN_EXCLUDE_URLS.append('^packages')
    LOGIN_EXCLUDE_URLS.append('^pkgsinfo/_package_json')
    LOGIN_EXCLUDE_URLS.append('^')

AUTH_ADFS = {
    'AUDIENCE': CLIENT_ID,
    'CLIENT_ID': CLIENT_ID,
    'CLIENT_SECRET': CLIENT_SECRET,
    'CLAIM_MAPPING': {'first_name': 'given_name',
                    'last_name': 'family_name',
                    'email': 'upn'},
    'MIRROR_GROUPS': True,
    'USERNAME_CLAIM': 'upn',
    'TENANT_ID': TENANT_ID,
    'RELYING_PARTY_ID': CLIENT_ID,
    'GROUPS_CLAIM': 'groups',
    "GROUP_TO_FLAG_MAPPING": {"is_staff": os.environ.get("STAFF_USERS", "").split(";"),
                              "is_superuser": os.environ.get("SUPER_USERS", "").split(";")},
    'LOGIN_EXEMPT_URLS': LOGIN_EXCLUDE_URLS,
}

# auth settings
AUTHENTICATION_BACKENDS = (
    'django.contrib.auth.backends.ModelBackend',
)
if USE_LDAP:
    AUTHENTICATION_BACKENDS + ('django_auth_ldap.backend.LDAPBackend',)

if CLIENT_SECRET:
    AdfsAuthCodeBackend = 'django_auth_adfs.backend.AdfsAuthCodeBackend'
    AdfsAccessTokenBackend= 'django_auth_adfs.backend.AdfsAccessTokenBackend'
    if ENTRA_ONLY:
        AUTHENTICATION_BACKENDS = AUTHENTICATION_BACKENDS + (AdfsAuthCodeBackend,)
    else:
        AUTHENTICATION_BACKENDS = AUTHENTICATION_BACKENDS + (AdfsAuthCodeBackend, AdfsAccessTokenBackend)

LOGIN_URL='/login/'
LOGIN_REDIRECT_URL = '/dashboard/'

if ENTRA_ONLY:
    LOGIN_URL = "django_auth_adfs:login"

ADMINS = (
     ('Local Admin', 'admin@example.com'),
)
MANAGERS = ADMINS