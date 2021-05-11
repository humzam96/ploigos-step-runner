"""`StepImplementer` for the `automated-governance` step using Rekor.

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

import os
import pprint
import sh
import re
import json
import base64
import textwrap
import subprocess
import hashlib

from pathlib import Path
import sys
from io import StringIO
from contextlib import redirect_stderr, redirect_stdout
from ploigos_step_runner import StepImplementer, StepResult, WorkflowResult
from ploigos_step_runner.utils.io import create_sh_redirect_to_multiple_streams_fn_callback
from ploigos_step_runner.utils.io import TextIOIndenter
from ploigos_step_runner.utils.dict import deep_merge



DEFAULT_CONFIG = {
}

REQUIRED_CONFIG_OR_PREVIOUS_STEP_RESULT_ARTIFACT_KEYS = [
    'rekor-server',
    'image-tar-file'
]


class Rekor(StepImplementer):  # pylint: disable=too-few-public-methods
    """`StepImplementer` for the `automated-governance` step using Rekor.
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

    @staticmethod
    def base64_encode(
            file_path
    ):
        """Given a file_path, read and encode the contents in base64
        Returns
        -------
        Base64Contents
            base64 encoded string of file contents
        """
        encoding = Path(file_path).read_text().encode('utf-8')
        return base64.b64encode(encoding).decode('utf-8')

    def get_image_hash(self, image_path):
        sha_stdout_result = StringIO()
        sha_stdout_callback = create_sh_redirect_to_multiple_streams_fn_callback([
            sys.stdout,
            sha_stdout_result
        ])
        return sh.sha256sum(  # pylint: disable=no-member
            image_path,
            _out=sha_stdout_callback,
            _err_to_out=True,
            _tee='out'
        )

    def create_rekor_entry( self,
        public_key_path,
        sig_file,
        image_tar_file,
        extra_data_file
    ):
        image_hash = self.get_image_hash(image_tar_file) #hashlib.sha256(artifact_file_path.read_bytes()).hexdigest()
        base64_encoded_artifact = self.base64_encode(extra_data_file)
        rekor_entry = {
            "kind": "rekord",
            "apiVersion": "0.0.1",
            "spec": {
                "signature": {
                    "format": "pgp",
                    "content": self.base64_encode(sig_file),
                    "publicKey": {
                        "content": self.base64_encode(public_key_path)
                    }
                },
                "data": {
                    "content": base64_encoded_artifact,
                    "hash": {
                        "algorithm": "sha256",
                        "value": image_hash
                    }
                },
                "extraData": base64_encoded_artifact
            }
        }
        return rekor_entry;

    def get_gpg_key(self, sig_file, image_tar_file):
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
            image_tar_file,
            _out=gpg_stdout_callback,
            _err_to_out=True,
            _tee='out'
        )
        return gpg_stdout_result

    def upload_to_rekor(self, rekor_server, image_tar_file, extra_data_file):
        sig_file = image_tar_file + '.asc'
        sig_file_path = Path(sig_file)
        if sig_file_path.exists():
            sig_file_path.unlink()
        self.get_gpg_key(sig_file,image_tar_file)
        rekor_entry = self.create_rekor_entry('/var/pgp-private-keys/gpg_public_key',sig_file, image_tar_file, extra_data_file)
        print("Rekor Entry: " + rekor_entry)
        rekor_entry_path = Path(os.path.join(self.work_dir_path, 'entry.json'))
        if rekor_entry_path.exists():
            rekor_entry_path.unlink()
        rekor_entry_path.write_text(json.dumps(rekor_entry).)
        rekor_upload_stdout_result = StringIO()
        rekor_upload_stdout_callback = create_sh_redirect_to_multiple_streams_fn_callback([
            sys.stdout,
            rekor_upload_stdout_result
        ])
        print("Rekor Entry: " + json.dumps(rekor_entry, indent=4))
        sh.rekor(
                'upload',
                '--rekor_server',
                rekor_server,
                '--entry',
                rekor_entry_path.absolute(),
                _out=rekor_upload_stdout_callback,
                _err_to_out=True,
                _tee='out'
                )

    def get_all_step_results_dict(self):
        """Get a dictionary of all of the recorded StepResults.

        Returns
        -------
        results: dict
            results of all steps from list
        """
        all_results = {}
        for step_result in self.workflow_result.workflow_list:
            all_results = deep_merge(
                dest=all_results,
                source=step_result.get_step_result_dict(),
                overwrite_duplicate_keys=True
            )
        step_runner_results = {
            'step-runner-results': all_results
        }
        return step_runner_results

    def _run_step(self):
        """Runs the step implemented by this StepImplementer.

        Returns
        -------
        StepResult
            Object containing the dictionary results of this step.
        """
        step_result = StepResult.from_step_implementer(self)
        image_tar_file = self.get_value('image-tar-file')
        rekor_server = self.get_value('rekor-server')

        all_workflows = self.get_all_step_results_dict()
        extra_data_file = os.path.join(self.work_dir_path, self.step_name+'.json')
        extra_data_file_path = Path(extra_data_file)
        if extra_data_file_path.exists():
            extra_data_file_path.unlink()
        extra_data_file_path.write_text(json.dumps(all_workflows))
        rekor_uuid = self.upload_to_rekor(rekor_server, image_tar_file, extra_data_file)

        return step_result
