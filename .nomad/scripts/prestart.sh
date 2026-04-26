mkdir --parents /assets/${NOMAD_JOB_NAME}/static/
cp --recursive --verbose static/* /assets/${NOMAD_JOB_NAME}/static/
flask --app checkpoint migrate
