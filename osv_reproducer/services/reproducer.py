import traceback

from .context import ContextService
from .builder import BuilderService
from .runner import RunnerService
from .verifier import VerifierService

from ..core.models import RunStatus
from ..core.common.enums import ReproductionMode
from ..core.exc import ContextError, BuilderError, RunnerError, VerifierError


class ReproducerService:
    def __init__(
            self, context_service: ContextService, builder_service: BuilderService, runner_service: RunnerService,
            verifier_service: VerifierService
    ):
        self._context = context_service
        self._builder = builder_service
        self._runner = runner_service
        self._verifier = verifier_service

    def __call__(
            self, osv_id: str, mode: ReproductionMode, build_extra_args: dict = None, reproduce: bool = False
    ) -> RunStatus:
        run_status = RunStatus()

        try:
            run_status.context_ok = self._context(osv_id, mode)
            run_status.builder_ok = self._builder(osv_id, mode, build_extra_args, reproduce=reproduce)
            run_status.runner_ok = self._runner(osv_id, mode)
            run_status.verifier_ok = self._verifier(osv_id, mode)
        except ContextError as e:
            run_status.error = str(e)
            run_status.exit_code = 2
            run_status.context_ok = False
        except BuilderError as e:
            run_status.error = str(e)
            run_status.exit_code = 2
            run_status.builder_ok = False
        except RunnerError as e:
            run_status.error = str(e)
            run_status.exit_code = 2
            run_status.runner_ok = False
        except VerifierError as e:
            run_status.error = str(e)
            run_status.exit_code = 2
            run_status.verifier_ok = False
        except Exception:
            run_status.error = str(traceback.format_exc())
            run_status.exit_code = 70

        return run_status
