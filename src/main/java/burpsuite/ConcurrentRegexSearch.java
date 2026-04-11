package burpsuite;

import burp.api.montoya.MontoyaApi;

import java.util.*;
import java.util.concurrent.Callable;
import java.util.regex.*;

/**
 * Holds all sensitive-data regex patterns pre-compiled once at startup.
 * Call {@link #initialize(MontoyaApi)} from the extension entry point before use.
 */
public class ConcurrentRegexSearch {

    /**
     * Map of human-readable name → pre-compiled Pattern.
     * Populated by {@link #initialize(MontoyaApi)}; never mutated after that.
     */
    private static final Map<String, Pattern> patternMap = new LinkedHashMap<>();

    /**
     * Compiles all patterns and logs any malformed ones to the Burp output tab.
     * Must be called once from {@code WebSocketChecker.initialize()} before any scan.
     */
    public static void initialize(MontoyaApi api) {
        // Raw name → regex string pairs.  Patterns are compiled below.
        Map<String, String> raw = new LinkedHashMap<>();

        raw.put("Adafruit IO Key",                          "aio_[a-zA-Z0-9]{28}");
        raw.put("Adobe OAuth Client Secret",                "p8e-[a-z0-9-]{32}");
        raw.put("Age Recipient (X25519 public key)",        "age1[0-9a-z]{58}");
        raw.put("Age Identity (X25519 secret key)",         "AGE-SECRET-KEY-1[0-9A-Z]{58}");
        raw.put("Artifactory API Key",                      "artifactory.{0,50}\\b([a-z0-9]{73})");
        raw.put("AWS API Key",                              "(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}");
        raw.put("AWS Secret Access Key",                    "aws_?(?:secret)?_?(?:access)?_?(?:key)?[\"''`]?\\s{0,30}(?::|=>|=)\\s{0,30}[\"''`]?([a-z0-9/+=]{40})");
        raw.put("AWS AppSync API Key",                      "da2-[a-z0-9]{26}");
        raw.put("AWS Account ID",                           "aws_?(?:account)_?(?:id)?[\"''`]?\\s{0,30}(?::|=>|=)\\s{0,30}[\"''`]?([0-9]{4}-?[0-9]{4}-?[0-9]{4})");
        raw.put("AWS Session Token",                        "(?:aws.?session|aws.?session.?token|aws.?token)[\"''`]?\\s{0,30}(?::|=>|=)\\s{0,30}[\"''`]?([a-z0-9/+=]{16,200})[^a-z0-9/+=]");
        raw.put("Amazon MWS Auth Token",                    "(amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})");
        raw.put("AWS S3 Bucket",                            "(?:^|[\\s/\"']|%2F)((?:[a-zA-Z0-9_-]+\\.)+(?:s3|s3-[a-z0-9-]+)\\.amazonaws\\.com)");
        raw.put("Amazon Resource Name",                     "(arn:(?:aws|aws-cn|aws-us-gov):[a-zA-Z0-9_-]{2,}:[a-z0-9-]*:\\d{12}:[^\\s\"'&<>\\\\%]+)");
        raw.put("AWS API Credentials",                      "(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\\b(?:(?s).{0,40})\\b([A-Za-z0-9/+=]{40})");
        raw.put("Azure Connection String",                  "(?i)(?:AccountName|SharedAccessKeyName|SharedSecretIssuer)\\s*=\\s*([^;]{1,80})\\s*;\\s*.{0,10}\\s*(?:AccountKey|SharedAccessKey|SharedSecretValue)\\s*=\\s*([^;]{1,100})(?:;|$)");
        raw.put("Azure App Configuration Connection String","(https://[a-zA-Z0-9-]+\\.azconfig\\.io);Id=([a-zA-Z0-9-]{4}-[a-zA-Z0-9-]{2}-[a-zA-Z0-9-]{2}:[a-zA-Z0-9+/]{18,22});Secret=([a-zA-Z0-9+/]{36,50}=)");
        raw.put("Azure Personal Access Token",              "(?i:ADO_PAT|pat_token|personal_?access_?token|\\$token)\\s*=\\s*[\"']([a-z0-9]{52})[\"']");
        raw.put("Bitbucket App Password",                   "ATBB[a-zA-Z0-9]{32}");
        raw.put("Blynk Device Access Token",                "https://(?:fra1\\.|lon1\\.|ny3\\.|sgp1\\.|blr1\\.)*blynk\\.cloud/external/api/[a-zA-Z0-9/]*\\?token=([a-zA-Z0-9_\\-]{32})(?:&|$)");
        raw.put("Blynk Organization Access Token",          "https://(?:fra1\\.|lon1\\.|ny3\\.|sgp1\\.|blr1\\.)*blynk\\.cloud/api/[a-zA-Z0-9_\\-\\s/\\\\]*-H\\s*\"Authorization:\\s*Bearer\\s*([a-zA-Z0-9_\\-]{40})\"");
        raw.put("CodeClimate Reporter ID",                  "(?:CODECLIMATE_REPO_TOKEN|CC_TEST_REPORTER_ID)\\s*[:=]\\s*([a-f0-9]{64})");
        raw.put("crates.io API Key",                        "cio[a-zA-Z0-9]{32}");
        raw.put("Databricks Personal Access Token",         "dapi[a-f0-9]{32}(?:-[0-9]+)?");
        raw.put("Dependency-Track API Key",                 "odt_[A-Za-z0-9]{32,255}");
        raw.put("DigitalOcean Application Access Token",    "doo_v1_[a-f0-9]{64}");
        raw.put("DigitalOcean Personal Access Token",       "dop_v1_[a-f0-9]{64}");
        raw.put("DigitalOcean Refresh Token",               "dor_v1_[a-f0-9]{64}");
        raw.put("Django Secret Key",                        "SECRET_KEY\\s*=\\s*r?[\"']([^\"'\\n]{5,100})[\"']");
        raw.put("Docker Hub Personal Access Token",         "dckr_pat_[a-zA-Z0-9_-]{27}");
        raw.put("Doppler CLI Token",                        "dp\\.ct\\.[a-zA-Z0-9]{40,44}");
        raw.put("Doppler Personal Token",                   "dp\\.pt\\.[a-zA-Z0-9]{40,44}");
        raw.put("Doppler Service Token",                    "dp\\.st\\.(?:[a-z0-9\\-_]{2,35}\\.)?[a-zA-Z0-9]{40,44}");
        raw.put("Doppler Service Account Token",            "dp\\.sa\\.[a-zA-Z0-9]{40,44}");
        raw.put("Doppler SCIM Token",                       "dp\\.scim\\.[a-zA-Z0-9]{40,44}");
        raw.put("Doppler Audit Token",                      "dp\\.audit\\.[a-zA-Z0-9]{40,44}");
        // BUG FIX: was missing the opening '(' before 'sl\.'
        raw.put("Dropbox Access Token",                     "(sl\\.[a-zA-Z0-9_-]{130,152})(?:$|[^a-zA-Z0-9_-])");
        raw.put("Dynatrace Token",                          "dt0[a-zA-Z]{1}[0-9]{2}\\.[A-Z0-9]{24}\\.[A-Z0-9]{64}");
        raw.put("Facebook Secret Key",                      "(?:facebook|fb).?(?:api|app|application|client|consumer|customer|secret|key).?(?:key|oauth|sec|secret)?.{0,30}[a-z0-9]{32}");
        raw.put("Facebook Access Token",                    "EAACEdEose0cBA[a-zA-Z0-9]+");
        raw.put("Figma Personal Access Token",              "figma.{0,20}\\b([0-9a-f]{4}-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})");
        raw.put("GitHub Personal Access Token",             "ghp_[a-zA-Z0-9]{36}");
        raw.put("GitHub OAuth Access Token",                "gho_[a-zA-Z0-9]{36}");
        raw.put("GitHub App Token",                         "(?:ghu|ghs)_[a-zA-Z0-9]{36}");
        raw.put("GitHub Refresh Token",                     "ghr_[a-zA-Z0-9]{76}");
        raw.put("GitHub Client ID",                         "(?:github).?(?:api|app|application|client|consumer|customer)?.?(?:id|identifier|key).{0,20}[a-z0-9]{20}");
        raw.put("GitHub Secret Key",                        "github.?(?:api|app|application|client|consumer|customer|secret|key).?(?:key|oauth|sec|secret)?.{0,20}[a-z0-9]{40}");
        raw.put("GitHub Personal Access Token (fine-grained)", "github_pat_[0-9a-zA-Z_]{82}");
        raw.put("GitLab Runner Registration Token",         "GR1348941[0-9a-zA-Z_-]{20}");
        raw.put("GitLab Personal Access Token",             "glpat-[0-9a-zA-Z_-]{20}");
        raw.put("GitLab Pipeline Trigger Token",            "glptt-[0-9a-f]{40}");
        raw.put("Google Client ID",                         "[0-9]+-[a-z0-9_]{32}\\.apps\\.googleusercontent\\.com");
        raw.put("Google OAuth Client Secret",               "GOCSPX-[a-zA-Z0-9_-]{28}");
        raw.put("Google OAuth Access Token",                "ya29\\.[0-9A-Za-z_-]{20,1024}");
        raw.put("Google API Key",                           "AIza[0-9A-Za-z_-]{35}");
        raw.put("Google Cloud Storage Bucket",              "(?:^|[\\s/\"']|%2F)((?:[a-zA-Z0-9_-]+\\.)+storage\\.googleapis\\.com)");
        // BUG FIX: was missing the opening '(' before the Google Client ID pattern
        raw.put("Google OAuth Credentials",                 "([0-9]+-[a-z0-9_]{32}\\.apps\\.googleusercontent\\.com)(?:(?s).{0,40})(?:(?i)client.?secret.{0,10})?((?:GOCSPX-[a-zA-Z0-9_-]{28})|(?:\\b[a-zA-Z0-9_-]{24}))");
        // BUG FIX: original pattern mixed two unrelated regexes into one invalid string
        raw.put("Hardcoded Gradle Credentials",             "credentials\\s*\\{(?:\\s*//.*)*\\s*(?:username|password)\\s+['\"]([^'\"]{1,60})['\"]");
        raw.put("Credentials in PostgreSQL Connection URI", "(?:postgres|postgresql)://([a-zA-Z0-9%;._~!$&'()*+,;=-]{3,}):([a-zA-Z0-9%;._~!$&'()*+,;=-]{3,})@([a-zA-Z0-9_.-]{3,}(?:\\:\\d{1,5})?)");
        raw.put("Postman API Key",                          "PMAK-[a-zA-Z0-9]{24}-[a-zA-Z0-9]{34}");
        raw.put("Credentials in PsExec",                   "psexec.{0,100}-u\\s*(\\S+)\\s+-p\\s*(\\S+)");
        raw.put("PyPI Upload Token",                        "pypi-AgEIcHlwaS5vcmc[a-zA-Z0-9_-]{50,}");
        raw.put("React App Username",                       "REACT_APP(?:_[A-Z0-9]+)*_USER(?:NAME)?\\s*=\\s*['\"]?([^\\s'\"$]{3,})");
        raw.put("React App Password",                       "REACT_APP(?:_[A-Z0-9]+)*_PASS(?:WORD)?\\s*=\\s*['\"]?([^\\s'\"$]{6,})");
        raw.put("RubyGems API Key",                         "rubygems_[a-f0-9]{48}");
        raw.put("Salesforce Access Token",                  "00[a-zA-Z0-9]{13}![a-zA-Z0-9._]{96}");
        raw.put("Sauce Token",                              "sauce.{0,50}\\b([a-f0-9-]{36})(?:[^a-f0-9-]|$)");
        raw.put("Segment Public API Token",                 "sgp_[a-zA-Z0-9]{64}");
        raw.put("SendGrid API Key",                         "SG\\.[0-9A-Za-z_-]{22}\\.[0-9A-Za-z_-]{43}");
        raw.put("Shopify Domain",                           "(?:[a-zA-Z0-9-]+\\.)*[a-zA-Z0-9-]+\\.myshopify\\.com");
        raw.put("Shopify App Secret",                       "shpss_[a-fA-F0-9]{32}");
        raw.put("Shopify Access Token (Public App)",        "shpat_[a-fA-F0-9]{32}");
        raw.put("Shopify Access Token (Custom App)",        "shpca_[a-fA-F0-9]{32}");
        raw.put("Shopify Access Token (Legacy Private App)","shppa_[a-fA-F0-9]{32}");
        raw.put("Slack Bot Token",                          "xoxb-[0-9]{10,12}-[0-9]{10,12}-[a-zA-Z0-9]{23,25}");
        raw.put("Slack User Token",                         "xoxp-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-f0-9]{32}");
        raw.put("Slack App Token",                          "xapp-[0-9]{12}-[a-zA-Z0-9/+]{24}");
        raw.put("Slack Legacy Bot Token",                   "xoxb-[0-9]{10,13}-[a-zA-Z0-9]{24}");
        raw.put("Slack Webhook",                            "https://hooks\\.slack\\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8,12}/[a-zA-Z0-9_]{24}");
        raw.put("SonarQube Token",                          "sonar.{0,5}login.{0,5}\\s*\\b([a-f0-9]{40})");
        raw.put("Square Access Token",                      "sq0atp-[a-z0-9_-]{22}");
        raw.put("Square OAuth Secret",                      "sq0csp-[a-z0-9_-]{43}");
        raw.put("StackHawk API Key",                        "hawk\\.[0-9A-Za-z_-]{20}\\.[0-9A-Za-z_-]{20}");
        raw.put("Stripe API Key",                           "(?:sk|rk)_live_[a-z0-9]{24}");
        raw.put("Stripe API Test Key",                      "(?:sk|rk)_test_[a-z0-9]{24}");
        raw.put("TeamCity API Token",                       "eyJ0eXAiOiAiVENWMiJ9\\.[A-Za-z0-9_-]{36}\\.[A-Za-z0-9_-]{48}");
        raw.put("Telegram Bot Token",                       "\\d+:AA[a-zA-Z0-9_-]{32,33}");
        raw.put("ThingsBoard Access Token",                 "thingsboard\\.cloud/api/v1/([a-z0-9]{20})");
        raw.put("ThingsBoard Provision Device Key",         "\"provisionDeviceKey\"\\s*:\\s*\"([a-z0-9]{20})\"");
        raw.put("ThingsBoard Provision Device Secret",      "\"provisionDeviceSecret\"\\s*:\\s*\"([a-z0-9]{20})\"");
        raw.put("TrueNAS API Key (REST API)",               "Bearer\\s*(\\d+-[a-zA-Z0-9]{64})");
        raw.put("TrueNAS API Key (WebSocket)",              "\"params\"\\s*:\\s*\\[\\s*\"(\\d+-[a-zA-Z0-9]{64})\"\\s*\\]");
        raw.put("Twilio API Key",                           "twilio.{0,20}\\b(sk[a-f0-9]{32})");
        raw.put("Twitter Client ID",                        "twitter.?(?:api|app|application|client|consumer|customer)?.?(?:id|identifier|key).{0,20}\\b([a-z0-9]{18,25})");
        raw.put("Twitter Secret Key",                       "twitter.?(?:api|app|application|client|consumer|customer|secret|key).?(?:key|oauth|sec|secret)?.{0,20}\\b([a-z0-9]{35,44})");
        raw.put("WireGuard Private Key",                    "PrivateKey\\s*=\\s*([A-Za-z0-9+/]{43})");
        raw.put("WireGuard Preshared Key",                  "PresharedKey\\s*=\\s*([A-Za-z0-9+/]{43})");

        // Compile each pattern once; log any malformed ones to the Burp output tab.
        for (Map.Entry<String, String> e : raw.entrySet()) {
            try {
                patternMap.put(e.getKey(), Pattern.compile(e.getValue()));
            } catch (PatternSyntaxException ex) {
                api.logging().logToOutput("[WebSocketChecker] Skipping malformed pattern '"
                        + e.getKey() + "': " + ex.getMessage());
            }
        }
    }

    /** Returns the map of pre-compiled patterns (unmodifiable). */
    public static Map<String, Pattern> getPatternMap() {
        return Collections.unmodifiableMap(patternMap);
    }

    /**
     * Callable that runs one pre-compiled Pattern against the message text.
     * Returns the pattern name paired with every match found.
     */
    static class RegexSearchTask implements Callable<Map.Entry<String, List<String>>> {
        private final String patternName;
        private final Pattern pattern;
        private final String inputText;

        RegexSearchTask(String patternName, Pattern pattern, String inputText) {
            this.patternName = patternName;
            this.pattern     = pattern;
            this.inputText   = inputText;
        }

        @Override
        public Map.Entry<String, List<String>> call() {
            List<String> matches = new ArrayList<>();
            Matcher matcher = pattern.matcher(inputText);
            while (matcher.find()) {
                matches.add(matcher.group());
            }
            return new AbstractMap.SimpleEntry<>(patternName, matches);
        }
    }
}