## What and why

<!-- What does this change, and what problem does it solve? Link issues with "Fixes #123". -->

## How it was tested

- [ ] `make lint` passes
- [ ] `make test` passes (`go test -race ./...`; set `REDIS_TEST_ADDR` to include the Redis tests)
- [ ] New or changed behaviour has tests

## Checklist

- [ ] No new third-party dependencies (RateGuard is standard library only)
- [ ] Docs updated (README, `docs/`) if behaviour, config or headers changed
- [ ] Security-relevant change reviewed against `docs/SECURITY.md`
- [ ] `CHANGELOG.md` updated for user-visible changes
