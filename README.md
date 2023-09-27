# AUTH service

The RDDL Auth service can be execute by running

```
poetry install
poetry run uvicorn auth.main:app --host 0.0.0.0 --port 8000
```

The configuration can be done by environment variable or by defining the environment variables in the ```.env``` file. An example ```.env``` file can be found at ```env-example```. Please adjust the variables and copy the file to ```.env```.

A docker container is build and run by running the following commands
```
docker build -t auth .
docker run --env JWT_SECRET='<jwt secret>' -d --name auth -p 80:80 auth
```
