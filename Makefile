# cmd must use tab, not 4 space.
# cmd must not has same name with directory in same directory.

install:
	pipenv install

# E501 Line lengths are recommended to be no greater than 79 characters (每行字符没什么要求)
# E731 Do not assign a lambda expression, use a def (在一些地方还是比较喜欢用 lambda)
# W503 Line break occurred before a binary operator (迷之规则)
pep8:
	pipenv run pycodestyle --ignore=E501,E731,W503 ./

server:
	pipenv run flask run

shell:
	pipenv run python shell.py

test:
	pipenv run pytest -sx test.py

venv:
	pipenv shell