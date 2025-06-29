from pathlib import Path

from gitlib.common.exceptions import GitLibException
from cement import App, TestApp
from cement.core.exc import CaughtSignal
from .core.exc import OSVReproducerError
from .controllers.base import Base
from .core.interfaces import HandlersInterface
from .handlers.github import GithubHandler
from .handlers.project import ProjectHandler


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
            Base, GithubHandler, ProjectHandler
        ]

        interfaces = [
            HandlersInterface
        ]

    @property
    def projects_dir(self):
        """
            Return the path to the projects folder.
        """
        projects_dir = Path.home() / ".osv_reproducer" / "projects"
        projects_dir.mkdir(exist_ok=True, parents=True)
        return projects_dir


class OSVReproducerTest(TestApp,OSVReproducer):
    """A sub-class of OSVReproducer that is better suited for testing."""

    class Meta:
        label = 'osv_reproducer'


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

        except GitLibException as e:
            print('GitLibError > %s' % e.args[0])
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
