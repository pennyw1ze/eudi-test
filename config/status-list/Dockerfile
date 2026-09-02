# Token status list service (revocation), from eudi-srv-statuslist-py.
#
# This mirrors the Dockerfile upstream ships in eudi-srv-pid-issuer/docker-compose,
# with one change: the source archive is copied in from the build context instead of
# being downloaded during the build. The upstream build fetches it from
# codeload.github.com, which stalls indefinitely on hosts whose build sandbox cannot
# reach it, even when the host itself can. `make statuslist-src` fetches it on the host.
FROM python:3.14.6-alpine3.24

COPY app.zip /tmp/app.zip
RUN unzip /tmp/app.zip && \
    mv eudi-srv-statuslist-py-* status-list && \
    rm /tmp/app.zip

WORKDIR /status-list

COPY get_status_list.py /tmp/get_status_list.py
RUN cat /tmp/get_status_list.py >> app/status_list_endpoints.py && rm /tmp/get_status_list.py

RUN sed -i 's|"url": "https://issuer.eudiw.dev"|"url": "https://localhost"|' app/static/swagger.json

RUN pip install --no-cache-dir Flask && \
    pip install --no-cache-dir -r app/requirements.txt

EXPOSE 5000

CMD [ "flask", "--app", "app", "run", "--host=0.0.0.0" ]
