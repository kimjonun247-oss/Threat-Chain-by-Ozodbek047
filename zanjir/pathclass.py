"""Where in a repository a finding lives: shipped code, or something beside it.

A scanner reports a hard-coded key in `tests/fixtures/` and one in
`app/settings.py` as the same kind of finding. On a small project that is a
handful of rows to read; on a large one the test tree, the examples, the
generated and the vendored code outnumber the code that is deployed, and the
findings that matter are buried under ones that cannot be reached in production.

This module only *names* the difference. Nothing is dropped because of it: every
finding stays in its report with a `path_class` beside it, and each consumer
decides what to do with that -- the chain rules do not build an "exposed service"
chain on a test fixture, and the CI gate can be told to judge shipped code only.

The classes, first match wins:

  vendored   someone else's code checked into the tree
  generated  build output or machine-written source
  test       tests, fixtures, mocks
  docs       documentation
  example    examples, samples, templates of configuration
  prod       everything else -- the default, so an unrecognised layout is never
             quietly treated as less important
"""
import re

PROD = 'prod'
CLASSES = ('vendored', 'generated', 'test', 'docs', 'example', PROD)

VENDORED_DIRS = frozenset({'vendor', 'vendors', 'third_party', 'third-party', 'thirdparty', 'node_modules',
                           'bower_components', 'site-packages', 'pods'})
# `build`, `out` and `target` are left out on purpose: they are also ordinary
# package names, and calling real source "generated" would hide it from a chain.
GENERATED_DIRS = frozenset({'dist', 'generated', '__generated__', '.next', '.nuxt', 'coverage', 'htmlcov'})
TEST_DIRS = frozenset({'test', 'tests', '__tests__', 'spec', 'specs', 'testing', 'testdata', 'test-data',
                       'test_data', 'fixtures', '__fixtures__', 'mocks', '__mocks__', 'e2e', 'cypress',
                       'integration-tests', 'unittests', 'unit-tests'})
DOCS_DIRS = frozenset({'docs', 'doc', 'documentation'})
EXAMPLE_DIRS = frozenset({'example', 'examples', 'sample', 'samples', 'demo', 'demos'})

GENERATED_FILE = re.compile(r'(\.min\.(js|css)|\.bundle\.js|\.pb\.go|_pb2(_grpc)?\.py|\.generated\.[a-z]+|\.g\.(dart|cs)'
                            r'|\.designer\.cs)$')
# Matched against the name as written: `UserTest.java` is a test, `Latest.java`
# is not, and only the capital letter tells them apart.
TEST_FILE = re.compile(r'^(test_.+\.py|conftest\.py|.+_test\.(py|go|rb|exs?)|.+\.(test|spec)\.[cm]?[jt]sx?'
                       r'|.+_spec\.rb|.+Tests?\.(java|kt|cs|php|scala)|Test[A-Z].*\.(java|kt))$')
DOCS_FILE = re.compile(r'\.(md|mdx|rst|adoc|txt)$')
EXAMPLE_FILE = re.compile(r'(\.(example|sample|template|dist|tmpl)$|\.(example|sample)\.[a-z0-9]+$)')


def classify(path):
    """The class of one repository-relative path. Never raises; unknown is prod."""
    raw = [part for part in str(path or '').replace('\\', '/').split('/') if part]
    if not raw:
        return PROD
    written, name, folders = raw[-1], raw[-1].lower(), {part.lower() for part in raw[:-1]}
    if folders & VENDORED_DIRS:
        return 'vendored'
    if folders & GENERATED_DIRS or GENERATED_FILE.search(name):
        return 'generated'
    if folders & TEST_DIRS or TEST_FILE.match(written):
        return 'test'
    if folders & DOCS_DIRS or DOCS_FILE.search(name):
        return 'docs'
    if folders & EXAMPLE_DIRS or EXAMPLE_FILE.search(name):
        return 'example'
    return PROD


def shipped(finding):
    """True unless the finding is known to sit outside shipped code.

    A finding with no path (a package, a URL, a Compose service) or one written
    before `path_class` existed is judged from its path, and counts as shipped
    when nothing says otherwise.
    """
    known = finding.get('path_class')
    return (known or classify(finding.get('path'))) == PROD
