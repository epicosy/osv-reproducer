from pathlib import Path
from cement import Controller, ex
from cement.utils.version import get_version_banner

from ..core.version import get_version
from ..core.common.enums import ReproductionMode
from ..utils.parse.arguments import parse_key_value_string
from ..services import ContextService, BuilderService, RunnerService, ReproducerService, VerifierService


VERSION_BANNER = """
Tooling for reproducing OSS-Fuzz bugs from OSV database %s
%s
""" % (get_version(), get_version_banner())


class Base(Controller):
    class Meta:
        label = 'base'

        # text displayed at the top of --help output
        description = 'A reproducer component that can compile OSS-Fuzz projects at specific versions and run test cases'

        # text displayed at the bottom of --help output
        epilog = 'Usage: osv_reproducer'

        # controller level arguments. ex: 'osv_reproducer --version'
        arguments = [
            ### add a version banner
            (['-v', '--version'], {'action': 'version', 'version': VERSION_BANNER}),
            (['-vb', '--verbose'], {'help': "Verbose mode.", 'action': 'store_true', 'default': False}),
            (['-oid', '--osv_id'], {
                'help': 'Identifier of the vulnerability in the OSV database (e.g., OSV-2023-XXXX)', 'type': str,
                'required': True
            }),
            (['-o', '--output-dir'], {
                'help': 'Directory to store output artifacts', 'type': str, 'default': "./osv-results"
            }),
            (['--build-extra-args'], {
                'help': "Additional build arguments to pass to the fuzzer container as environment variables. Format: 'KEY1:VALUE1|KEY2:VALUE2'",
                'type': str, 'default': ""
            })
        ]

    def _post_argument_parsing(self):
        if self.Meta.label == 'base':
            path_obj = Path(self.app.pargs.output_dir).expanduser().resolve()

            if path_obj.is_dir() and not path_obj.exists():
                path_obj.mkdir(parents=True, exist_ok=True)

            file_provision_handler_cls = self.app.handler.get("handlers", "file_provision")
            file_provision_handler = file_provision_handler_cls(path_obj)
            file_provision_handler._setup(self.app)

            docker_handler = self.app.handler.get("handlers", "docker", setup=True)

            context_service = ContextService(
                file_provision_handler=file_provision_handler,
                github_handler=self.app.handler.get("handlers", "github", setup=True),
                osv_handler=self.app.handler.get("handlers", "osv", setup=True),
                oss_fuzz_handler=self.app.handler.get("handlers", "oss_fuzz", setup=True),
                gcs_handler=self.app.handler.get("handlers", "gcs", setup=True)
            )

            builder_service = BuilderService(
                file_provision_handler=file_provision_handler, docker_handler=docker_handler
            )
            runner_service = RunnerService(
                file_provision_handler=file_provision_handler, docker_handler=docker_handler
            )
            verifier_service = VerifierService(
                file_provision_handler=file_provision_handler
            )
            self.reproducer_service = ReproducerService(
                context_service=context_service, builder_service=builder_service, runner_service=runner_service,
                verifier_service=verifier_service
            )

    def _default(self):
        """Default action if no sub-command is passed."""
        self.app.args.print_help()

    @ex(help='Reproduce a given OSS-Fuzz vulnerability in the OSV database.')
    def reproduce(self):
        build_args = parse_key_value_string(self.app.pargs.build_extra_args)

        self.app.log.info(f"Starting reproduction of crash for {self.app.pargs.osv_id}")

        run_status = self.reproducer_service(
            osv_id=self.app.pargs.osv_id,
            mode=ReproductionMode.CRASH,
            build_extra_args=build_args,
            reproduce=True
        )

        self.app.log.info(str(run_status))

        if run_status.error:
            self.app.log.error(run_status.error)

        # TODO: maybe should add a flag
        if run_status.exit_code is not None:
            exit(run_status.exit_code)

    @ex(help='Verify if the patched version addresses the issue for a given OSS-Fuzz Issue in the OSV database.')
    def verify(self):
        self.app.log.info(f"Starting verification of patch for {self.app.pargs.osv_id}")
        run_status = self.reproducer_service(
            osv_id=self.app.pargs.osv_id,
            mode=ReproductionMode.FIX
        )

        # TODO: maybe should add a flag
        if run_status.exit_code is not None:
            exit(run_status.exit_code)
