from pathlib import Path

from gitlib.common.exceptions import GitLibException

from cement import App
from cement.core.exc import CaughtSignal

from .core.exc import OSVReproducerError
from .controllers.base import Base
from .core.interfaces import HandlersInterface

from .handlers.gcs import GCSHandler
from .handlers.osv import OSVHandler
from .handlers.build import BuildHandler
from .handlers.runner import RunnerHandler
from .handlers.github import GithubHandler
from .handlers.project import ProjectHandler
from .handlers.oss_fuzz import OSSFuzzHandler


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
            Base, GithubHandler, ProjectHandler, OSVHandler, GCSHandler, BuildHandler, OSSFuzzHandler,
            RunnerHandler
        ]

        interfaces = [
            HandlersInterface
        ]

    @property
    def app_dir(self):
        path = Path.home() / ".osv_reproducer"
        path.mkdir(exist_ok=True, parents=True)
        return path

    @property
    def projects_dir(self):
        """
            Return the path to the projects folder.
        """
        path = Path.home() / ".osv_reproducer" / "projects"
        path.mkdir(exist_ok=True, parents=True)
        return path

    @property
    def issues_dir(self):
        path = Path.home() / ".osv_reproducer" / "issues"
        path.mkdir(exist_ok=True, parents=True)
        return path

    @property
    def testcases_dir(self):
        path = Path.home() / ".osv_reproducer" / "testcases"
        path.mkdir(exist_ok=True, parents=True)
        return path

    @property
    def snapshots_dir(self):
        path = Path.home() / ".osv_reproducer" / "snapshots"
        path.mkdir(exist_ok=True, parents=True)
        return path


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
