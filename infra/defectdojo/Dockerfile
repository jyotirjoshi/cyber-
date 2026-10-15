FROM defectdojo/defectdojo-django:3.3.200

USER root
COPY start-defectdojo.sh /start-defectdojo.sh
RUN chmod 0755 /start-defectdojo.sh
USER 1001

ENTRYPOINT ["/start-defectdojo.sh"]
