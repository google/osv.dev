lib-tests:
	./run_tests.sh

worker-tests:
	cd docker/worker && ./run_tests.sh

importer-tests:
	cd docker/importer && ./run_tests.sh

appengine-tests:
	cd gcp/appengine && ./run_tests.sh

lint:
	tools/lint_and_format.sh

# TODO: API integration tests.
all-tests: lib-tests worker-tests importer-tests appengine-tests
