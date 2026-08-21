# Clanker jail

A file-system sandbox for your clanker.

The defaults are expected to work OOTB, other than two inconveniences:
1. Specifying which clanker to jail is mandatory.
2. `$PWD` is read-only. This is a safe default per _author's opinion_ because allowing writes should be opt-in, not opt-out.

## Environment variables

`clanker-jail` exports `IN_CLANKER_JAIL` as `1`, which you may use to modify the agent's behaviour (allow/prompt certain tool calls, etc).

Other environment variables like `PI_TELEMETRY=0` are also set (without overriding your defaults). More details in `src/exec.rs`.

## Notice

**A sandboxed clanker isn't to be trusted 100%.** It simply means that you can worry a little less.
**_No networking sandboxing is implemented._**
