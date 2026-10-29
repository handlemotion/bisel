#if BISEL_DEV_FIXTURE
import Foundation

// =====================================================================================
//  DEV FIXTURE — NOT A REAL VAULT.
//  ~200 fake logins used to build and verify the command panel and the fill engine
//  before BiselCore exists. Every password is the literal string "FIXTURE-<id>-NOT-A-REAL-PASSWORD",
//  every TOTP is a fake pseudo-code (changes every 30 s). Compiled only when BISEL_DEV_FIXTURE is set
//  (Debug configuration in project.yml; never Release).
//  The panel footer shows a "DEV FIXTURE" badge whenever this source is active.
//  Replace by a `VaultSearchSource` / `VaultSecretProvider` backed by BiselCore.
// =====================================================================================

@MainActor
final class DevFixtureVault: VaultSearchSource, VaultSecretProvider {
    let isUnlocked = true
    let provenanceLabel: String? = "DEV FIXTURE"

    private let index: FuzzySearchIndex
    private let records: [String: SearchRecord]

    init() {
        let all = Self.makeRecords()
        index = FuzzySearchIndex(records: all)
        records = Dictionary(uniqueKeysWithValues: all.map { ($0.id, $0) })
        Log.app.notice("DEV FIXTURE vault active: \(all.count) FAKE items, no real secrets")
    }

    func search(_ query: String, limit: Int) -> [VaultSearchResult] {
        index.search(query, limit: limit).map {
            VaultSearchResult(id: $0.id, title: $0.title, username: $0.username, domain: $0.domain, tags: $0.tags)
        }
    }

    func recordUse(id: String) { index.recordUse(id: id) }

    func secret(_ kind: SecretKind, for id: String) async throws -> String {
        guard let r = records[id] else { throw VaultError.notFound }
        switch kind {
        case .username: return r.username
        case .password: return "FIXTURE-\(r.id)-NOT-A-REAL-PASSWORD"
        case .totp:
            // NOT real TOTP: a stable pseudo-code that changes every 30 s so the reveal countdown can be seen.
            let step = Int(Date().timeIntervalSince1970) / 30
            var h: UInt64 = 1469598103934665603
            for b in "\(r.id)|\(step)".utf8 { h = (h ^ UInt64(b)) &* 1099511628211 }
            return String(format: "%06d", Int(h % 1_000_000))
        }
    }

    func url(for id: String) -> URL? { records[id]?.urls.first.flatMap(URL.init(string:)) }

    // MARK: generation (deterministic, so runs are reproducible)

    private static let sites: [(String, String)] = [
        ("GitHub", "github.com"), ("GitLab", "gitlab.com"), ("Google", "accounts.google.com"),
        ("Apple ID", "appleid.apple.com"), ("Amazon", "amazon.com"), ("Netflix", "netflix.com"),
        ("Spotify", "accounts.spotify.com"), ("Cloudflare", "dash.cloudflare.com"), ("Vercel", "vercel.com"),
        ("Linear", "linear.app"), ("Notion", "notion.so"), ("Figma", "figma.com"), ("Slack", "slack.com"),
        ("Discord", "discord.com"), ("Dropbox", "dropbox.com"), ("1Password", "my.1password.com"),
        ("Stripe", "dashboard.stripe.com"), ("PayPal", "paypal.com"), ("Wise", "wise.com"),
        ("BBVA", "bbva.mx"), ("Banorte", "banorte.com"), ("Nu", "nu.com.mx"), ("Mercado Libre", "mercadolibre.com.mx"),
        ("Uber", "auth.uber.com"), ("Airbnb", "airbnb.com"), ("Booking", "booking.com"), ("Expedia", "expedia.com"),
        ("Twitter", "x.com"), ("LinkedIn", "linkedin.com"), ("Reddit", "reddit.com"), ("Hacker News", "news.ycombinator.com"),
        ("Medium", "medium.com"), ("Substack", "substack.com"), ("YouTube", "youtube.com"), ("Twitch", "twitch.tv"),
        ("Steam", "store.steampowered.com"), ("Epic Games", "epicgames.com"), ("Adobe", "account.adobe.com"),
        ("Microsoft", "login.live.com"), ("Azure", "portal.azure.com"), ("AWS Console", "signin.aws.amazon.com"),
        ("DigitalOcean", "cloud.digitalocean.com"), ("Fly.io", "fly.io"), ("Render", "dashboard.render.com"),
        ("PlanetScale", "app.planetscale.com"), ("Sentry", "sentry.io"), ("Datadog", "app.datadoghq.com"),
        ("npm", "npmjs.com"), ("PyPI", "pypi.org"), ("Docker Hub", "hub.docker.com"), ("Homebrew", "brew.sh"),
        ("Zoom", "zoom.us"), ("Calendly", "calendly.com"), ("Mailchimp", "login.mailchimp.com"),
        ("Namecheap", "namecheap.com"), ("GoDaddy", "godaddy.com"), ("Porkbun", "porkbun.com"),
        ("Fastmail", "fastmail.com"), ("ProtonMail", "account.proton.me"), ("Hey", "hey.com"),
        ("Zapier", "zapier.com"), ("Airtable", "airtable.com"), ("Asana", "app.asana.com"), ("Trello", "trello.com"),
        ("Shopify", "accounts.shopify.com"), ("Squarespace", "squarespace.com"), ("Webflow", "webflow.com"),
        ("Coursera", "coursera.org"), ("Duolingo", "duolingo.com"), ("Kindle", "read.amazon.com"),
        ("IKEA", "ikea.com"), ("Walmart", "walmart.com.mx"), ("Liverpool", "liverpool.com.mx"),
        ("CFE", "cfe.mx"), ("SAT", "sat.gob.mx"), ("IMSS", "imss.gob.mx"), ("Telmex", "telmex.com"),
    ]
    private static let variants = ["", " (work)", " (personal)", " (old)", " (shared)", " (admin)", " (test)"]
    private static let people = ["rodrigo", "rjimenez", "rod.dev", "jimenezzr05", "hola", "admin", "ops", "billing", "luna", "mateo"]
    private static let tagPool = ["work", "personal", "finance", "dev", "social", "shopping", "travel", "infra", "mail", "gov"]

    private struct SplitMix64 {
        var s: UInt64
        mutating func next() -> UInt64 {
            s &+= 0x9E3779B97F4A7C15
            var z = s
            z = (z ^ (z >> 30)) &* 0xBF58476D1CE4E5B9
            z = (z ^ (z >> 27)) &* 0x94D049BB133111EB
            return z ^ (z >> 31)
        }
        mutating func pick<T>(_ a: [T]) -> T { a[Int(next() % UInt64(a.count))] }
    }

    private static func makeRecords() -> [SearchRecord] {
        var rng = SplitMix64(s: 0xB15E1)
        var out: [SearchRecord] = []
        let now = Date()
        var n = 0
        // Diacritics: "cafe"/"café", "credito"/"crédito" must find these.
        for (i, (name, host)) in [("Café de Tacuba", "cafedetacuba.mx"), ("Crédito Banorte", "banorte.com"),
                                  ("Zürich Versicherung", "zurich.ch")].enumerated() {
            out.append(SearchRecord(id: String(format: "fd%03d", i), title: name, username: "luna@example.test",
                                    urls: ["https://\(host)/login"], tags: ["personal"], lastUsed: now.addingTimeInterval(-86_400 * 30), useCount: 1))
        }
        // Icon test items: real domains (icons are fetched from these sites) + one dead domain.
        for (i, (name, host)) in [("GitHub (icon test)", "github.com"), ("Cloudflare (icon test)", "cloudflare.com"),
                                  ("Apple (icon test)", "apple.com"), ("Defunct site (icon test)", "dead.bisel-fixture.invalid")].enumerated() {
            out.append(SearchRecord(id: String(format: "fi%03d", i), title: name, username: "icons@example.test",
                                    urls: ["https://\(host)/"], tags: ["icon-test"], lastUsed: now, useCount: 99))
        }
        while out.count < 200 {
            let (name, host) = sites[n % sites.count]
            let round = n / sites.count
            let variant = round == 0 ? "" : variants[(round * 3 + n) % variants.count]
            let user = rng.pick(people)
            let email = "\(user)@example.test"
            let tags = Array(Set([rng.pick(tagPool), rng.pick(tagPool)])).sorted()
            let age = Double(rng.next() % (60 * 86_400))
            out.append(SearchRecord(
                id: String(format: "fx%03d", n),
                title: name + variant,
                username: round % 2 == 0 ? email : user,
                urls: ["https://\(host)/login"],
                tags: tags,
                lastUsed: now.addingTimeInterval(-age),
                useCount: Int(rng.next() % 40)))
            n += 1
        }
        return out
    }
}
#endif
