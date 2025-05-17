# monitoring/views.py

from django.http import JsonResponse
from django.contrib.sessions.models import Session
from django.utils import timezone
from django.contrib.auth.models import User
from django.conf import settings
import logging

logger = logging.getLogger(__name__)

def active_users_count(request):
    try:
        now = timezone.now()
        # Filter for sessions that have not expired
        active_sessions = Session.objects.filter(expire_date__gte=now)
        user_ids = set()
        for session in active_sessions:
            data = session.get_decoded()
            user_id = data.get('_auth_user_id')
            if user_id:
                user_ids.add(user_id)
        active_user_count = len(user_ids)
        logger.info(f"Active user count: {active_user_count}")
        return JsonResponse({'active_user_count': active_user_count})
    except Exception as e:
        logger.error(f"Error in active_users_count: {e}")
        return JsonResponse({'error': 'An error occurred'}, status=500)


# get active users
def get_active_users(request):
    try:
        now = timezone.now()
        active_sessions = Session.objects.filter(expire_date__gte=now)
        user_ids = set()
        user_data = []
        for session in active_sessions:
            data = session.get_decoded()  # Entschlüsselt die session_data
            user_id = data.get('_auth_user_id')  # User-ID auslesen
            if user_id and user_id not in user_ids:
                user_ids.add(user_id)
                try:
                    user = User.objects.get(id=user_id)
                    last_activity = session.expire_date - timezone.timedelta(seconds=settings.SESSION_COOKIE_AGE)
                    user_data.append({
                        "id": user.id,
                        "username": user.username,
                        "email": user.email,
                        "first_name": user.first_name,
                        "last_name": user.last_name,
                        "last_activity": last_activity.strftime('%Y-%m-%d %H:%M:%S')
                    })
                except User.DoesNotExist:
                    logger.warning(f"User {user_id} nicht gefunden")
        return JsonResponse({'active_users': user_data}, json_dumps_params={"ensure_ascii": False})
    except Exception as e:
        logger.error(f"Error in get_active_users: {e}")
        return JsonResponse({'error': 'An error occurred'}, status=500)