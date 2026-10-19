"""Destination boot choices must affect only a newly booted snapshot child."""

import os
from contextlib import suppress

import pytest

from integration.helpers import IMAGE, remove_sandbox
from microsandbox import InitConfig, Sandbox


@pytest.mark.asyncio
@pytest.mark.parametrize("full", [False, True])
async def test_snapshot_destination_init_and_hostname(sandbox_name, full):
    if full and os.environ.get("MSB_BOOT_TEST_FULL") != "1":
        pytest.skip("full-memory capture requires qualified firmware")
    source_name = sandbox_name("boot-src")
    names = [source_name]
    group = None
    source = await Sandbox.create(
        source_name, image=IMAGE, cpus=1, memory=256, hostname="source-host"
    )
    try:
        assert (await source.shell("printf source-marker > /root/marker; sync")).success
        result = await source.snapshot(
            sandbox_name("boot-history"), full=full, record_integrity=True
        )
        group, checkpoint = result.snapshot, result.checkpoint
        digest = checkpoint.digest
        before = await checkpoint.verify()
        if full:
            for options in [{"init": "auto"}, {"hostname": "source-host"}]:
                for progress in [False, True]:
                    name = sandbox_name("boot-refuse")
                    names.append(name)
                    with pytest.raises(Exception, match="disk-only"):
                        if progress:
                            session = await group.spawn_sandbox_with_progress(name=name, **options)
                            await session.result()
                        else:
                            await checkpoint.spawn_sandbox(name=name, **options)
                    # No child should have been registered before refusing the boot mutation.
                    with pytest.raises(Exception, match="not found"):
                        await Sandbox.get(name)
        # The source remains unchanged while both public spawn paths boot private children.
        for progress in [False, True]:
            name = sandbox_name("boot-child")
            names.append(name)
            options = dict(
                name=name,
                cpus=1,
                memory=256,
                hostname="child-host",
                disk_only=full,
                init=InitConfig(
                    "/bin/sh",
                    args=["-c", 'printf "%s" "$BOOT_VALUE" > /root/boot-value; exec sleep 300'],
                    env={"BOOT_VALUE": "child-init"},
                ),
            )
            if progress:
                session = await checkpoint.spawn_sandbox_with_progress(**options)
                child = await session.result()
            else:
                child = await group.spawn_sandbox(**options)
            try:
                output = await child.shell(
                    'for i in $(seq 1 50); do test -s /root/boot-value && break; sleep 0.1; done; '
                    'test "$(cat /root/boot-value)" = child-init && '
                    'test "$(cat /root/marker)" = source-marker && '
                    'test "$(hostname)" = child-host && cat /proc/1/comm'
                )
                assert output.success, output.stderr_text
                assert output.stdout_text.strip() == "sleep"
                assert (await child.shell("printf child-change > /root/marker")).success
            finally:
                # The test PID 1 is sleep and intentionally has no shutdown handler.
                await child.kill()
                await remove_sandbox(name)
            original = await source.shell(
                'test ! -e /root/boot-value && test "$(hostname)" = source-host && cat /root/marker'
            )
            assert original.success
            assert original.stdout_text == "source-marker"
        assert checkpoint.digest == digest
        assert await checkpoint.verify() == before
    finally:
        with suppress(Exception):
            await source.stop()
        for name in reversed(names):
            await remove_sandbox(name)
        if group is not None:
            await group.remove()
