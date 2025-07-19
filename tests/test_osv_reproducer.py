from cement import TestApp
from osv_reproducer.main import OSVReproducer


class OSVReproducerTest(TestApp,OSVReproducer):
    """A sub-class of OSVReproducer that is better suited for testing."""

    class Meta:
        label = 'osv_reproducer'

        # Add a default configuration for testing
        config_defaults = {
            'osv_reproducer': {},
            'tokens': {
                'github': 'test_token'
            }
        }


def test_osv_reproducer():
    # test osv_reproducer without any subcommands or arguments
    with OSVReproducerTest() as app:
        app.run()
        assert app.exit_code == 0


def test_osv_reproducer_debug():
    # test that debug mode is functional
    argv = ['--debug']
    with OSVReproducerTest(argv=argv) as app:
        app.run()
        assert app.debug is True
