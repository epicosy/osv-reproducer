from ..core.exc import BuilderError
from ..core.models import ReproductionContext
from ..core.common.enums import ReproductionMode
from ..core.interfaces import DockerInterface, FileProvisionInterface


class BuilderService:
    def __init__(self, file_provision_handler: FileProvisionInterface, docker_handler: DockerInterface):
        self.docker_handler = docker_handler
        self.file_provision_handler = file_provision_handler

    def _build_project_base_image(self, project_name: str, oss_fuzz_repo_sha: str) -> str:
        image_tag = f"osv-reproducer/{project_name}-{oss_fuzz_repo_sha}:latest"

        # if the image exists, return its tag
        if not self.docker_handler.check_image_exists(image_tag):
            project_path = self.file_provision_handler.get_project_path(project_name, oss_fuzz_repo_sha)

            if not project_path:
                raise BuilderError(f"Project {project_name} not found in the file provisioner")

            if not self.docker_handler.build_image(
                context_path=project_path, tag=image_tag, remove_containers=False
            ):
                raise BuilderError(f"Failed to build project {project_name}: image {image_tag} not found after build")

        return image_tag

    def _build_project_fuzzer_container(
            self, context: ReproductionContext, image_name: str, repositories: dict, extra_args: dict = None,
            reproduce: bool = False
    ) -> str:
        platform = 'linux/arm64' if context.issue_report.architecture == 'aarch64' else 'linux/amd64'

        # Environment variables for the container
        environment = {
            'FUZZING_ENGINE': 'libfuzzer' if reproduce else context.issue_report.fuzzing_engine.lower(),
            'FUZZING_LANGUAGE': context.project_info.language,
            'SANITIZER': context.issue_report.sanitizer,
            'ARCHITECTURE': context.issue_report.architecture,
            'PROJECT_NAME': context.issue_report.project,
            'HELPER': 'True'
        }

        if extra_args:
            environment.update(extra_args)

        output_dir = self.file_provision_handler.get_output_path(context.id, context.mode.value, mkdir=True)

        # Volumes to mount
        volumes = {
            str(output_dir): {'bind': '/out', 'mode': 'rw'},
            # str(work_dir): {'bind': '/work', 'mode': 'rw'} # enable if needed
        }

        for key, _v in repositories.items():
            local_dir = self.file_provision_handler.get_repository_path(**_v)

            if not local_dir:
                raise BuilderError(
                    f"Repository {_v['owner']}/{_v['name']}@{_v['version']} not found in the file provisioner"
                )

            print(f"Mounting {local_dir} to {key}")
            volumes[str(local_dir)] = {'bind': key, 'mode': 'rw'}

        for project_file, mount_file in context.mount_files.items():
            local_file = self.file_provision_handler.get_project_file_path(
                context.project_info.name, context.project_info.oss_fuzz_repo_sha, project_file
            )

            if not local_file:
                raise BuilderError(f"Project file {project_file} not found in the file provisioner")

            print(f"Mounting {local_file} to {mount_file}")
            volumes[str(local_file)] = {'bind': mount_file, 'mode': 'ro'}

        # Run the container
        if not self.docker_handler.run_container(
                image=image_name,
                container_name=context.fuzzer_container_name,
                platform=platform,
                environment=environment,
                volumes=volumes,
                tty=False,
                stdin_open=True
        ):
            raise BuilderError(f"Failed to run container {context.fuzzer_container_name}: empty container ID returned")

        # Stream and display logs in real-time
        self.docker_handler.stream_container_logs(context.fuzzer_container_name)

        # if there is an error in the build process, we should find it at the end of the logs
        error_code = self.docker_handler.find_log_error_code(context.fuzzer_container_name)

        if error_code:
            raise BuilderError(f"Build failed with error code {error_code}")

        if self.docker_handler.check_container_exit_code(context.fuzzer_container_name) != 0:
            raise BuilderError(f"Build failed with non-zero exit code")

        return context.fuzzer_container_name

    def __call__(self, osv_id: str, mode: ReproductionMode, build_extra_args: dict, reproduce: bool = False):
        context = self.file_provision_handler.load_context(osv_id, mode)

        if not context:
            raise BuilderError(f"Context for OSV {osv_id} in mode {mode.value} not found")

        base_image_tag = self._build_project_base_image(
            project_name=context.project_info.name, oss_fuzz_repo_sha=context.project_info.oss_fuzz_repo_sha
        )

        # Check if container with this name already exists
        if self.docker_handler.check_container_exists(context.fuzzer_container_name):
            # Check if the container can be reused
            if self.docker_handler.check_container_exit_status(context.fuzzer_container_name):
                error_code = self.docker_handler.find_log_error_code(context.fuzzer_container_name)

                if not error_code:
                    return True

            self.docker_handler.remove_container(context.fuzzer_container_name)

        self._build_project_fuzzer_container(
            context, image_name=base_image_tag, repositories=context.repositories, extra_args=build_extra_args,
            reproduce=reproduce
        )

        return True
