FROM python:2.7-slim
WORKDIR /srv
RUN pip install --no-cache-dir flask==1.1.4 werkzeug==1.0.1 jinja2==2.11.3 markupsafe==1.1.1 \
    itsdangerous==1.1.0 click==7.1.2 sqlalchemy==1.3.24 simplejson==3.17.6 web.py==0.51 \
    cheroot==8.6.0 more-itertools==5.0.0 "jaraco.functools<3" six "backports.functools_lru_cache<2"
COPY AndroLabServer/ /srv/
EXPOSE 8888
CMD ["python", "app.py"]
