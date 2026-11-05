# bisel-bench: what launch, unlock and the panel cost

Two measurements, both on a seeded box of made-up logins. Nothing here touches a real box.

**Headless, repeatable.** The core and the app's search sources (`Sources/bisel-bench/App` links to them), in release, no UI:

    cd apps/mac/Tools/bisel-bench
    swift build -c release
    BISEL_ALLOW_SOFTWARE_KEYS=1 BISEL_BENCH_DIR=/tmp/bench .build/out/Products/Release/bisel-bench --items 5000 --runs 15 --json out.json

**In the app, one launch.** `app-perf.sh` runs an optimized Debug build on a throwaway copy of that box. `PanelBoxPerf` measures launch,
panel, scrolling and settings inside that launch, writes medians and quits. The panel is invisible, the global hotkey is off, site icons
are off. It writes nothing when the box locked or a jump did not land on its row.

    Tools/bisel-bench/app-perf.sh --build /tmp/perf-build
    Tools/bisel-bench/app-perf.sh /tmp/bench/bisel-bench-5000 out.json /tmp/perf-build

Never run it in a loop (AGENTS.md). Reading the numbers:

- Compare two builds back to back, and swap the order once. Launch marks before `did finish launching` depend mostly on whether the
  binary ran before and on what is in the page cache, not on the code: only compare second launches of each binary.
- Settings pages nothing changed are the noise floor of a run (about 6% back to back; 30% on a busy Mac).
