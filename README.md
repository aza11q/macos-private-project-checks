# Native checks for a separately maintained private project

This repository contains only the build controller and workflow for the desktop
project associated with it. The application source is maintained in a separate
private repository. Standard public GitHub-hosted Mac runners execute its native
checks; this workflow refuses to run in a private repository.

Only manual dispatch is enabled. A read-only deploy key grants access to that
single private source repository. The key is exposed to the checkout step only
and removed from the runner filesystem immediately after checkout. No personal
access token is copied into this repository.

The source repository, requirement path, command argument list and result paths
are configured as GitHub Actions secrets. Detailed command output stays in local
runner files. Only an age-encrypted result archive is uploaded. The age public
recipient is a repository variable; its private decryption key remains on the
owner's computer and is never uploaded to GitHub.

Manual dispatch can select the standard macOS 15 or macOS 26 Apple Silicon
image. Intel checks use the standard macOS 15 Intel image. The optional secondary
command slot uses a separate PRIVATE_COMMAND_SECONDARY secret so another command
can run without changing the primary command of an already queued check.

The workflow, controller, job status, architecture and source commit hash are
public. The owner must trust everyone who can modify this controller or the
workflow. Application files and detailed logs are not committed to this public
repository or uploaded as plaintext artifacts.

References:
- https://docs.github.com/en/actions/reference/runners/github-hosted-runners
- https://docs.github.com/en/authentication/connecting-to-github-with-ssh/managing-deploy-keys
- https://github.com/FiloSottile/age
