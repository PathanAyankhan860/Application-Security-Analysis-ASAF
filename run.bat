@echo off

if [%1]==[] goto usage
SET conf=%1
goto :run

:usage
SET conf="0.0.0.0:8000 [::]:8000"

:run
echo Clearing previous ASAF login sessions...
poetry run python manage.py shell -c "from django.contrib.sessions.models import Session; Session.objects.all().delete()"

echo Running ASAF on %conf%
poetry run waitress-serve --listen=%conf% --threads=10 --channel-timeout=3600 mobsf.MobSF.wsgi:application