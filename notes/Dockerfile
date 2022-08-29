
FROM node:16
RUN apt-get update -y \
    && apt-get -y install curl python build-essential git ca-certificates
ENV DEBUG="notes:*,messages:*"
ENV SEQUELIZE_CONNECT="models/sequelize-docker-mysql.yaml"
ENV NOTES_MODEL="sequelize"
ENV USER_SERVICE_URL="http://svc-userauth:5858"
ENV PORT="3000"





RUN mkdir -p /notesapp /notesapp/minty /notesapp/partials/notesapp/public /notesapp/routes /notesapp/theme /notesapp/theme/dist/notesapp/views
COPY minty/ /notesapp/minty/
COPY models/*.mjs models/*.yaml /notesapp/models/
COPY partials/ /notesapp/partials/
COPY config/ /notesapp/config
COPY public/ /notesapp/public/
COPY routes/ /notesapp/routes/
COPY theme/dist/ /notesapp/theme/dist/
COPY views/ /notesapp/views/
COPY *.mjs package.json /notesapp/
WORKDIR /notesapp
RUN npm install --unsafe-perm
VOLUME /sessions
EXPOSE 3000
CMD [ "node", "./app.mjs" ]