import traceback

from .runner import RunnerService
from .builder import BuilderService
from .context import ContextService

from ..core.models import RunStatus
from ..core.common.enums import ReproductionMode
from ..core.exc import ContextError, BuilderError, RunnerError


class ReproducerService:
    def __init__(self, context_service: ContextService, builder_service: BuilderService, runner_service: RunnerService):
        self._context = context_service
        self._builder = builder_service
        self._runner = runner_service

    def __call__(self, osv_id: str, mode: ReproductionMode, build_extra_args: dict = None) -> RunStatus:
        run_status = RunStatus()

        try:
            context = self._context(osv_id, mode)
            run_status.context_ok = True
            self._builder(context, build_extra_args)
            run_status.build_ok = True
            verification = self._runner(context)
            run_status.fuzzing_ok = True
            run_status.verification_ok = verification.success
        except ContextError as e:
            run_status.error = str(e)
            run_status.exit_code = 2
            run_status.context_ok = False
        except BuilderError as e:
            run_status.error = str(e)
            run_status.exit_code = 2
            run_status.build_ok = False
        except RunnerError as e:
            run_status.error = str(e)
            run_status.exit_code = 2
            run_status.fuzzing_ok = False
        except Exception:
            run_status.error = str(traceback.format_exc())
            run_status.exit_code = 70

        return run_status
