"""`StepImplementer` for the `generate-metadata` step using Maven.

Step Configuration
------------------
Step configuration expected as input to this step.
Could come from:

  * static configuration
  * runtime configuration
  * previous step results

Configuration Key | Required? | Default     | Description
------------------|-----------|-------------|-----------

Result Artifacts
----------------
Results artifacts output by this step.

Result Artifact Key | Description
--------------------|------------
"""

import os.path
import sh
import json
import base64
from pathlib import Path
import sys
from io import StringIO

from ploigos_step_runner import StepImplementer, StepResult
from ploigos_step_runner.utils.io import create_sh_redirect_to_multiple_streams_fn_callback

DEFAULT_CONFIG = {
}

REQUIRED_CONFIG_OR_PREVIOUS_STEP_RESULT_ARTIFACT_KEYS = [
    'rekor-server',
    'package-artifacts',
    'configlint-yml-path',
    'sonarqube-result-set',
    'maven-output',
    'image-tar-file',
    'html-report',
    'xml-report',
    'stdout-report',
    'container-image-signature-private-key-fingerprint',
    'container-image-signature-file-path',
    'argocd-deployed-manifest',
    'configlint-result-set'
    'surefire-reports',
    'cucumber-report-json',
]


class Maven(StepImplementer):  # pylint: disable=too-few-public-methods
    """`StepImplementer` for the `generate-metadata` step using Maven.
    """

    @staticmethod
    def step_implementer_config_defaults():
        """Getter for the StepImplementer's configuration defaults.

        Returns
        -------
        dict
            Default values to use for step configuration values.

        Notes
        -----
        These are the lowest precedence configuration values.

        """
        return DEFAULT_CONFIG

    @staticmethod
    def _required_config_or_result_keys():
        """Getter for step configuration or previous step result artifacts that are required before
        running this step.

        See Also
        --------
        _validate_required_config_or_previous_step_result_artifact_keys

        Returns
        -------
        array_list
            Array of configuration keys or previous step result artifacts
            that are required before running the step.
        """
        return REQUIRED_CONFIG_OR_PREVIOUS_STEP_RESULT_ARTIFACT_KEYS

    def base64_encode(
            file_path
    ):
        """Given a file_path, read and encode the contents in base64
        Returns
        -------
        Base64Contents
            base64 encoded string of file contents
        """

        # Assume the file is text and catch Unicode exception if not
        encoding = None

        try:
            encoding = Path(file_path).read_text().encode('ascii')
        except UnicodeDecodeError:
            encoding = Path(file_path).read_bytes()
            pass

        return base64.b64encode(encoding).decode('ascii')

    def create_rekor_entry( self,
        artifact_file_path,
        public_key_path,
        signature_file_path,
    ):
        artifact_hash = hashlib.sha256(artifact_file_path.read_bytes()).hexdigest()
        # print(f"Hash is {artifact_hash}")
        base64_encoded_artifact = self.base64_encode(artifact_file_path)

        rekor_entry = {
            "kind": "rekord",
            "apiVersion": "0.0.1",
            "spec": {
                "signature": {
                    "format": "pgp",
                    "content": self.base64_encode(signature_file_path),
                    "publicKey": {
                        "content": self.base64_encode(public_key_path)
                    }
                },
                "data": {
                    "content": base64_encoded_artifact,
                    "hash": {
                        "algorithm": "sha256",
                        "value": artifact_hash
                    }
                },
                "extraData": base64_encoded_artifact
            }
        }

        return rekor_entry;


    def get_gpg_key(self, sig_file, artifact_file):
        # NOTE: GPG is weird in that it sends "none error" output to stderr even on success...
        #       so merge the stderr into stdout
        gpg_stdout_result = StringIO()
        gpg_stdout_callback = create_sh_redirect_to_multiple_streams_fn_callback([
            sys.stdout,
            gpg_stdout_result
        ])
        sh.gpg(  # pylint: disable=no-member
            '--armor',
            '-u',
            'tssc-service-account@redhat.com',
            '--output',
            sig_file,
            '--detach-sign',
            artifact_file,
            _out=gpg_stdout_callback,
            _err_to_out=True,
            _tee='out'
        )
        return gpg_stdout_result

    def upload_to_rekor(self, artifact_file):
        rekor_server = self.get_value('rekor-server')
        sig_file = artifact_file + '.asc'
        sig_file_path = Path(sig_file)
        if sig_file_path.exists():
            sig_file_path.unlink()
        self.get_gpg_key(sig_file,artifact_file)
        artifact_file_path = Path(os.path.realpath(artifact_file))
        rekor_entry = self.create_rekor_entry(artifact_file_path,'/var/pgp-private-keys/gpg_public_key',sig_file)
        rekor_entry_path = Path(os.path.join(self.work_dir_path, 'entry.json'))
        if rekor_entry_path.exists():
            rekor_entry_path.unlink()
        rekor_entry_path.write_text(json.dumps(rekor_entry))
        rekor_upload_stdout_result = StringIO()
        rekor_upload_stdout_callback = create_sh_redirect_to_multiple_streams_fn_callback([
            sys.stdout,
            rekor_upload_stdout_result
        ])

        rekor = sh.rekor(
                        'upload',
                        '--rekor_server',
                        rekor_server,
                        '--entry',
                        rekor_entry_path.absolute(),
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       universal_newlines=True)
        if rekor.returncode != 0:
            return rekor.stderr
        return rekor.stdout



    def get_image_hash(self, artifact_file):
        sha_stdout_result = StringIO()
        sha_stdout_callback = create_sh_redirect_to_multiple_streams_fn_callback([
            sys.stdout,
            gpg_stdout_result
        ])
        sh.sha256sum(  # pylint: disable=no-member
            artifact_file,
            _out=sha_stdout_callback,
            _err_to_out=True,
            _tee='out'
        )
        return sha_stdout_result



    def _run_step(self):
        """Runs the step implemented by this StepImplementer.

        Returns
        -------
        StepResult
            Object containing the dictionary results of this step.
        """
        step_result = StepResult.from_step_implementer(self)

        for x in _required_config_or_result_keys():
            print(x)
            if x != 'rekor-server':
                # json_file = Path(x.value) #Path(os.path.join(self.work_dir_path, self.step_name+'.json'))
                # if json_file.exists():
                #     json_file.unlink()
                # json_file.write_text()
                rekor_uuid = self.upload_to_rekor(self.get_value(x)) #os.path.join(self.work_dir_path, self.step_name+'.json'))

        return step_result