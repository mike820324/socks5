test:
	python -m unittest discover

lint:
	@flake8 && echo "Static Check Without Error"

coverage:
	@coverage run --source=socks5 -m unittest discover
