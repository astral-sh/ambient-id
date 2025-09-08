# ambient-id

A library for accessing ambient OIDC credentials in a variety of environments.

This crate serves the same purpose as Python's [id] library.

## Supported environments

`ambient-id` currently supports ambient OIDC credential detection in the
following environments:

* GitHub Actions

  - GitHub Actions requires the `id-token: write` permission to be set
    at the job or workflow level. In general, users should set this at the
    job level to limit the scope of the permission.

* GitLab CI

  - On GitLab, this crate looks for an `<AUD>_ID_TOKEN` environment variable,
    where `<AUD>` is the audience string with non-alphanumeric characters
    replaced by underscores and converted to uppercase. For example, if the
    audience is `sigstore`, the crate will look for a `SIGSTORE_ID_TOKEN`
    environment variable.

    For additional information on `<AUD>_ID_TOKEN` environment variables,
    see the [GitLab documentation].

[id]: https://pypi.org/project/id/

[GitLab documentation]: https://docs.gitlab.com/ci/secrets/id_token_authentication/
