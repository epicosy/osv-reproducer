from cement import App

from .controllers.base import Base
from .core.exc import OSVReproducerError

from .handlers import HandlersInterface

from .handlers.gcs import GCSHandler
from .handlers.osv import OSVHandler
from .handlers.docker import DockerHandler
from .handlers.github import GithubHandler
from .handlers.oss_fuzz import OSSFuzzHandler
from .handlers.file_provision import FileProvisionHandler


class OSVReproducer(App):
    """OSV Reproducer primary application."""

    class Meta:
        label = 'osv_reproducer'

        # call sys.exit() on close
        exit_on_close = True

        # load additional framework extensions
        extensions = [
            'yaml',
            'colorlog',
            'jinja2',
        ]

        # configuration handler
        config_handler = 'yaml'

        # configuration file suffix
        config_file_suffix = '.yml'

        # set the log handler
        log_handler = 'colorlog'

        # set the output handler
        output_handler = 'jinja2'

        # register handlers
        handlers = [
            Base, GithubHandler, OSVHandler, DockerHandler, GCSHandler, OSSFuzzHandler, FileProvisionHandler
        ]

        interfaces = [
            HandlersInterface
        ]


def main():
    with OSVReproducer() as app:
        try:
            app.run()

        except AssertionError as e:
            print('AssertionError > %s' % e.args[0])
            app.exit_code = 1

            if app.debug is True:
                import traceback
                traceback.print_exc()

        except OSVReproducerError as e:
            print('OSVReproducerError > %s' % e.args[0])
            app.exit_code = 1

            if app.debug is True:
                import traceback
                traceback.print_exc()

        #except CaughtSignal as e:
            # Default Cement signals are SIGINT and SIGTERM, exit 0 (non-error)
        #    print('\n%s' % e)
        #    app.exit_code = 0


if __name__ == '__main__':
    main()
