# Developing FoD in Docker

## Quickstart

In the top directory of the repository, run `docker-compose up`.

This will start containers for `redis`, `mariadb`, `celery` (which currently
includes ExaBGP), then `fod` itself (same as `celery` but runs a development
web server), one router container, and two host containers.

The repo is mounted as a volume in the `fod` and `celery` containers, so
editing files in the repo will be immediately reflected in the containers.
Both the development web server and the `celery` daemon are invoked using
Django's own `manage.py`, so when you save a file, both the web server and
`celery` will restart with the new changes.

## Visual Studio Code

Configuration is also provided in `.devcontainer` for running FoD with the
Dev Containers extension of Visual Studio Code. To do this, open the top
level directory with VS Code (e.g. by typing `code .`), open the command
panel with cmd-shift-P, and select "Dev Containers: Reopen in Container".

The terminal will open in the `fod` container. You will need to start
the development server yourself, with:

```
source venv/bin/activate
./manage.py runserver 0.0.0.0:8000
```

Logs of the development web server will appear in your terminal. To see
the celery logs, open another terminal and `tail -f log/celery_jobs.log`.
