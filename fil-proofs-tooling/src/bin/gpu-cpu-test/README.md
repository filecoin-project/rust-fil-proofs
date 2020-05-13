GPU CPU Test
============

This is a test utility to test whether it works to prioritize certain proofs. When a proof is prioritized, it will run on the GPU and all other proofs will be pushed to the CPU.

This utility is meant to be run manually. It spawns multiple threads/processes that run proofs. Those get killed after 5 minutes of running. The overall test runs longer as some input data needs to be generated. By default, one thread/process will always be prioritized to run on the GPU. The other one might be moved to the CPU.

To check whether the prioritization is working, run it first with default parameters:

    $ RUST_LOG=debug cargo run --release --bin gpu-cpu-test

Occasionally you should see log messaged like

    2020-05-15T12:35:48.680 366073 low-02 WARN bellperson::gpu::locks > GPU acquired by a high priority process! Freeing up Multiexp kernels...


which indicate that the high priority proof indeed pushes lower priority ones down from the GPU onto the CPU.

Once the test is completed there should be log messages that contain the results, the number of proofs run per thread:

    Thread high info: RunInfo { elapsed: 301.714277787s, iterations: 51 }
    Thread low-01 info: RunInfo { elapsed: 306.615414259s, iterations: 15 }
    Thread low-02 info: RunInfo { elapsed: 303.641817512s, iterations: 17 }

The high priority proof clearly was able to run more proofs than the lower priority ones.

To double check the result, you can also run the test without special priorities. Then the number of proofs run should be similar across all the threads as you can see below (the first thread is always called `high` even if it doesn't run with high priority):

    $ RUST_LOG=debug cargo run --release --bin gpu-cpu-test -- --gpu-stealing=false
    Thread high info: RunInfo { elapsed: 307.515676843s, iterations: 34 }
    Thread low-01 info: RunInfo { elapsed: 305.585567866s, iterations: 34 }
    Thread low-02 info: RunInfo { elapsed: 302.7105106s, iterations: 34 }
