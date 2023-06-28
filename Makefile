clean: clean-build clean-pyc clean-test

clean-build:
	rm -fr build/
	rm -fr dist/
	rm -fr .eggs/
	find . -name '*.egg-info' -exec rm -fr {} +
	find . -name '*.egg' -exec rm -f {} +

clean-pyc:
	find . -name '*.pyc' -exec rm -f {} +
	find . -name '*.pyo' -exec rm -f {} +
	find . -name '*~' -exec rm -f {} +
	find . -name '__pycache__' -exec rm -fr {} +

clean-test:
	rm -fr .tox/
	rm -f .coverage
	rm -fr htmlcov/


test: clean-test
	-pytest --cov=fastapi_auth0 --cov-report=term-missing tests/ -v -s
	mypy fastapi_auth0 --python-version 3.11 --strict

test-single-module: clean-test
	pytest $(module) -v -s

install: clean 
	poetry install 


test-app:clean-test
	-docker compose run --rm  app
	-pytest tests/test_app_auth.py -v -s
	docker compose down 