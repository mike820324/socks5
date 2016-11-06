test:
	python -B -m unittest discover

lint:
	@flake8 && echo "Static Check Without Error"

coverage:
	@coverage run --source=socks5 -m unittest discover

build-pkg:
	@python setup.py sdist

test-deploy:
	@python setup.py sdist register -r testpypi
	@python setup.py sdist upload -r testpypi

deploy:
	@python setup.py sdist register -r pypi
	@python setup.py sdist upload -r pypi

clean:
	rm -rf dist
	rm -rf socks5.egg-info
