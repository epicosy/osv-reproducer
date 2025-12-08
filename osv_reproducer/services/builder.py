# TODO: replace with domain interface/model
from docker.models.containers import Container

from ..core.exc import BuilderError
from ..core.models import ReproductionContext
from ..utils.parse.log import find_make_error
from ..core.interfaces import DockerInterface, FileProvisionInterface


class BuilderService:
    def __init__(self, file_provision_handler: FileProvisionInterface, docker_handler: DockerInterface):
        self.docker_handler = docker_handler
        self.file_provision_handler = file_provision_handler

    def get_project_base_image(self, project_name: str, oss_fuzz_repo_sha: str) -> str:
        """
        Build the base image of a project.

        Args:
            project_name: Project name.
            oss_fuzz_repo_sha: SHA of the OSS-Fuzz repo.

        Returns:
            str: ID of the built Docker image.

        Raises:
            FuzzerError: If building the project fails.
        """
        try:
            image_tag = f"osv-reproducer/{project_name}-{oss_fuzz_repo_sha}:latest"

            # if the image exists, return its tag
            if self.docker_handler.check_image_exists(image_tag):
                return image_tag

            project_path = self.file_provision_handler.get_project_path(project_name, oss_fuzz_repo_sha)

            if not project_path:
                raise BuilderError(f"Project {project_name} not found in the file provisioner")

            image_id = self.docker_handler.build_image(
                context_path=project_path, tag=image_tag, remove_containers=False
            )

            if not image_id:
                raise BuilderError(f"Failed to build project {project_name}: empty image ID returned")

            if not self.docker_handler.check_image_exists(image_tag):
                raise BuilderError(f"Failed to build project {project_name}: image {image_tag} not found after build")

            return image_tag
        except Exception as e:
            raise BuilderError(f"Failed to build project {project_name}: {str(e)}")

    def build_project_fuzzer_container(
            self, context: ReproductionContext, image_name: str, repositories: dict, extra_args: dict = None
    ) -> Container:
        """
        Run a Docker container for fuzzing a project and display its logs.

        Args:
            context: The reproduction context.
            image_name: Docker image to use.
            repositories: Repositories to mount.
            extra_args: Additional arguments to pass to the fuzzer. If None, uses the default arguments.

        Returns:
            str: name of the created or existing container.

        Raises:
            FuzzerError: If running the container fails.
        """
        try:
            platform = 'linux/arm64' if context.issue_report.architecture == 'aarch64' else 'linux/amd64'

            # Environment variables for the container
            environment = {
                'FUZZING_ENGINE': context.issue_report.fuzzing_engine.lower(),
                'FUZZING_LANGUAGE': context.project_info.language,
                'SANITIZER': context.issue_report.sanitizer,
                'ARCHITECTURE': context.issue_report.architecture,
                'PROJECT_NAME': context.issue_report.project,
                'HELPER': 'True'
            }

            if extra_args:
                environment.update(extra_args)

            output_dir = self.file_provision_handler.get_output_path(context.id, context.mode.value)

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

            # Run the container
            container = self.docker_handler.run_container(
                image=image_name,
                container_name=context.fuzzer_container_name,
                platform=platform,
                environment=environment,
                volumes=volumes,
                tty=False,
                stdin_open=True
            )

            # Stream and display logs in real-time
            logs = self.docker_handler.stream_container_logs(container)

            # if there is an error in the build process, we should find it at the end of the logs
            error_code = find_make_error(logs[-10:])

            if error_code:
                raise BuilderError(f"Build failed with error code {error_code}")

            return container
        except Exception as e:
            raise BuilderError(f"Failed to run container {context.fuzzer_container_name}: {str(e)}")

    def __call__(self, context: ReproductionContext, build_extra_args: dict) -> Container:
        """
        Set up and build the fuzzer container for reproduction or verification.

        Args:
            context: The reproduction context
            build_extra_args: Additional build arguments

        Returns:
            The fuzzer container

        Raises:
            FuzzerError: If the fuzzer container exits with non-zero code
        """
        base_image_tag = self.get_project_base_image(
            project_name=context.project_info.name, oss_fuzz_repo_sha=context.project_info.oss_fuzz_repo_sha
        )

        # Check if container with this name already exists
        fuzzer_container = self.docker_handler.check_container_exists(context.fuzzer_container_name)

        if fuzzer_container:
            # Check if the container can be reused
            if self.docker_handler.check_container_exit_status(fuzzer_container):
                # TODO: this should be done by the docker handler
                logs = fuzzer_container.logs(tail=10).decode("utf-8").strip().split("\n")

                # if there is an error in the build process, we should find it at the end of the logs
                error_code = find_make_error(logs)

                if not error_code:
                    return fuzzer_container

                print(f"Previous build failed with error code {error_code}")

            # TODO: this should be done by the docker handler
            print(f"Removing existing container {context.fuzzer_container_name} to run a new build")
            fuzzer_container.remove(force=True)

        # TODO: should check the snapshot against a dependency dict to make sure it includes all dependencies
        fuzzer_container = self.build_project_fuzzer_container(
            context, image_name=base_image_tag, repositories=context.repositories, extra_args=build_extra_args
        )

        if self.docker_handler.check_container_exit_code(fuzzer_container) != 0:
            raise BuilderError(f"Fuzzer container for {context.issue_report.id} exited with non-zero exit code")

        return fuzzer_container
