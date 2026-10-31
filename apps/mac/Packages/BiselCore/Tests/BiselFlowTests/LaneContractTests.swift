#if BISEL_SOFTWARE_KEYS
import Testing
import BiselLaneContract

// The lane contract (docs/SYNC-LANES.md §10). The flows live in BiselLaneContract so the signed app can run the same ones
// against CloudKit (project.contract.yml, opt-in, never here or in CI). Here they run on the in-memory `FakeLane` and the
// real server (`wrangler dev`, local D1); the storage-only and hostile-storage flows run on `FakeLane` only.

enum LaneUnderTest: String, CaseIterable, Sendable, CustomTestStringConvertible {
    case fake, server
    var testDescription: String { rawValue }
    var lane: ContractLane { self == .fake ? .fake : .server }
}

@Suite("Lane contract: the same flows on every lane", .serialized)
struct LaneContractTests {
    @Test("every lane", arguments: LaneContract.flows.map(\.name), LaneUnderTest.allCases)
    func contract(_ flow: String, _ lane: LaneUnderTest) async throws {
        report(await LaneContract.run(try #require(LaneContract.flow(named: flow)), on: lane.lane))
    }

    @Test("a lane that is only storage", arguments: LaneContract.storageOnly.map(\.name))
    func storageOnly(_ flow: String) async throws {
        report(await LaneContract.run(try #require(LaneContract.flow(named: flow)), on: .fake))
    }

    @Test("a lane that is only storage and misbehaves", arguments: LaneContract.hostile.map(\.name))
    func hostileStorage(_ flow: String) async throws {
        report(await LaneContract.run(try #require(LaneContract.flow(named: flow)), on: .fake))
    }

    private func report(_ failures: [Checks.Failure]) {
        for f in failures {
            Issue.record(Comment(rawValue: f.message), sourceLocation: SourceLocation(fileID: f.fileID, filePath: f.filePath, line: f.line, column: 1))
        }
    }
}
#endif
