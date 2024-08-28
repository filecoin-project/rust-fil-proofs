GitHub Actions setup
====================

The main CI is happening in the [`ci.yml`], this is where the test are run.

There is a separate workflow called [`proof-params-generate.yml`], that pre-generates the Groth16 parameter files needed for testing. Those parameters are stored as GitHub Artifacts, which are then downloaded by any workflow that needs them. Those artifacts are available for 90 days. Hence this job runs every to months to regenerate them, but also to have enough time in case something breaks.

The [`proof-params-download` Action] is a helper for downloading the pre-generated Groth16 parameters.

[`ci.yml`]: ./workflows/ci.yml
[`proof-params-generate.yml`]: ./workflows/proof-params-generate.yml
[`proof-params-download` Action]: ./actions/proof-params-download/action.yml
