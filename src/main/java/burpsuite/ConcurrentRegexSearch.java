package burpsuite;

import java.util.*;
import java.util.concurrent.Callable;
import java.util.regex.*;

public class ConcurrentRegexSearch {
    private static final Map<String, String> regexMap = new HashMap<>();

    static {
        regexMap.put("Adafruit IO Key", "aio_[a-zA-Z0-9]{28}");
        regexMap.put("Adobe OAuth Client Secret", "p8e-[a-z0-9-]{32}");
        regexMap.put("Age Recipient (X25519 public key)", "age1[0-9a-z]{58}");
        regexMap.put("Age Identity (X22519 secret key)", "AGE-SECRET-KEY-1[0-9A-Z]{58}");
        regexMap.put("Artifactory API Key", "artifactory.{0,50}\\b([a-z0-9]{73})");
        regexMap.put("AWS API Key", "(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}");
        regexMap.put("AWS Secret Access Key", "aws_?(?:secret)?_?(?:access)?_?(?:key)?[\"''`]?\\s{0,30}(?::|=>|=)\\s{0,30}[\"''`]?([a-z0-9/+=]{40})");
        regexMap.put("Segment Public API Token", "sgp_[a-zA-Z0-9]{64}");
        regexMap.put("SendGrid API Key", "SG\\.[0-9A-Za-z_-]{22}\\.[0-9A-Za-z_-]{43}");
        regexMap.put("Shopify Domain", "(?:[a-zA-Z0-9-]+\\.)*[a-zA-Z0-9-]+\\.myshopify\\.com");
        regexMap.put("Shopify App Secret", "shpss_[a-fA-F0-9]{32}");
        regexMap.put("Shopify Access Token (Public App)", "shpat_[a-fA-F0-9]{32}");
        regexMap.put("Shopify Access Token (Custom App)", "shpca_[a-fA-F0-9]{32}");
        regexMap.put("Shopify Access Token (Legacy Private App)", "shppa_[a-fA-F0-9]{32}");
        regexMap.put("Slack Bot Token", "xoxb-[0-9]{10,12}-[0-9]{10,12}-[a-zA-Z0-9]{23,25}");
        regexMap.put("Slack User Token", "xoxp-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-f0-9]{32}");
        regexMap.put("Slack App Token", "xapp-[0-9]{12}-[a-zA-Z0-9/+]{24}");
        regexMap.put("Slack Legacy Bot Token", "xoxb-[0-9]{10,13}-[a-zA-Z0-9]{24}");
        regexMap.put("TrueNAS API Key (REST API)", "Bearer\\s*(\\d+-[a-zA-Z0-9]{64})");
        regexMap.put("Twilio API Key", "twilio.{0,20}\\b(sk[a-f0-9]{32})");
        regexMap.put("Twitter Client ID", "twitter.?(?:api|app|application|client|consumer|customer)?.?(?:id|identifier|key).{0,2}\\s{0,20}.{0,2}\\s{0,20}.{0,2}\\b([a-z0-9]{18,25})");
        regexMap.put("Twitter Secret Key", "twitter.?(?:api|app|application|client|consumer|customer|secret|key).?(?:key|oauth|sec|secret)?.{0,2}\\s{0,20}.{0,2}\\s{0,20}.{0,2}\\b([a-z0-9]{35,44})");
        regexMap.put("WireGuard Private Key", "PrivateKey\\s*=\\s*([A-Za-z0-9+/]{43})");
        regexMap.put("WireGuard Preshared Key", "PresharedKey\\s*=\\s*([A-Za-z0-9+/]{43})");
        regexMap.put("Doppler CLI Token", "dp\\.ct\\.[a-zA-Z0-9]{40,44}");
        regexMap.put("Doppler Personal Token", "dp\\.pt\\.[a-zA-Z0-9]{40,44}");
        regexMap.put("Doppler Service Token", "dp\\.st\\.(?:[a-z0-9\\-_]{2,35}\\.)?[a-zA-Z0-9]{40,44}");
        regexMap.put("Doppler Service Account Token", "dp\\.sa\\.[a-zA-Z0-9]{40,44}");
        regexMap.put("Doppler SCIM Token", "dp\\.scim\\.[a-zA-Z0-9]{40,44}");
        regexMap.put("Doppler Audit Token", "dp\\.audit\\.[a-zA-Z0-9]{40,44}");
        regexMap.put("Dropbox Access Token", "sl\\.[a-zA-Z0-9_-]{130,152})(?:$|[^a-zA-Z0-9_-])");
        regexMap.put("Dynatrace Token", "dt0[a-zA-Z]{1}[0-9]{2}\\.[A-Z0-9]{24}\\.[A-Z0-9]{64}");
        regexMap.put("Sauce Token", "sauce.{0,50}\\b([a-f0-9-]{36})(?:[^a-f0-9-]|$)");
        regexMap.put("Slack Webhook", "https://hooks.slack.com/services/T[a-z0-9_]{8}/B[a-z0-9_]{8,12}/[a-z0-9_]{24}");
        regexMap.put("SonarQube Token", "sonar.{0,5}login.{0,5}\\s*\\b([a-f0-9]{40})");
        regexMap.put("Square Access Token", "sq0atp-[a-z0-9_-]{22}");
        regexMap.put("Square OAuth Secret", "sq0csp-[a-z0-9_-]{43}");
        regexMap.put("StackHawk API Key", "hawk\\.[0-9A-Za-z_-]{20}\\.[0-9A-Za-z_-]{20}");
        regexMap.put("Stripe API Key", "(?:sk|rk)_live_[a-z0-9]{24}");
        regexMap.put("Stripe API Test Key", "(?:sk|rk)_test_[a-z0-9]{24}");
        regexMap.put("AWS AppSync API Key", "da2-[a-z0-9]{26}");
        regexMap.put("AWS Account ID", "aws_?(?:account)_?(?:id)?[\"''`]?\\s{0,30}(?::|=>|=)\\s{0,30}[\"''`]?([0-9]{4}-?[0-9]{4}-?[0-9]{4})");
        regexMap.put("AWS Session Token", "(?:aws.?session|aws.?session.?token|aws.?token)[\"''`]?\\s{0,30}(?::|=>|=)\\s{0,30}[\"''`]?([a-z0-9/+=]{16,200})[^a-z0-9/+=]");
        regexMap.put("Amazon MWS Auth Token", "(amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})");
        regexMap.put("AWS S3 Bucket", "(?:^|[\\s/\"']|%2F)((?:[a-zA-Z0-9_-]+\\.)+(?:s3|s3-af-south-1|s3-ap-east-1|s3-ap-northeast-1|s3-ap-northeast-2|s3-ap-northeast-3|s3-ap-south-1|s3-ap-south-2|s3-ap-southeast-1|s3-ap-southeast-2|s3-ap-southeast-3|s3-ap-southeast-4|s3-ca-central-1|s3-eu-central-1|s3-eu-central-2|s3-eu-north-1|s3-eu-south-1|s3-eu-south-2|s3-eu-west-1|s3-eu-west-2|s3-eu-west-3|s3-me-central-1|s3-me-south-1|s3-sa-east-1|s3-us-east-1|s3-us-east-2|s3-us-gov-east-1|s3-us-gov-west-1|s3-us-west-1|s3-us-west-2)\\.amazonaws\\.com)");
        regexMap.put("Amazon Resource Name", "(arn:(?:aws|aws-cn|aws-us-gov):[a-zA-Z0-9_-]{2,}:(?:af-south-1|ap-east-1|ap-northeast-1|ap-northeast-2|ap-northeast-3|ap-south-1|ap-south-2|ap-southeast-1|ap-southeast-2|ap-southeast-3|ap-southeast-4|ca-central-1|eu-central-1|eu-central-2|eu-north-1|eu-south-1|eu-south-2|eu-west-1|eu-west-2|eu-west-3|me-central-1|me-south-1|sa-east-1|us-east-1|us-east-2|us-gov-east-1|us-gov-west-1|us-west-1|us-west-2)?:(?:\\d{12})?:(?:[a-zA-Z0-9_-]+[:/])?[^\\s\"'&<>\\\\%]+)(?:[\\s\"'&<>\\\\%]|$)");
        regexMap.put("AWS API Credentials", "(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\\b(?:(?s).{0,40})\\b([A-Za-z0-9/+=]{40})");
        regexMap.put("Azure Connection String", "(?x)(?i)(?:AccountName|SharedAccessKeyName|SharedSecretIssuer)\\s*=\\s*([^;]{1,80})\\s*;\\s*.{0,10}\\s*(?:AccountKey|SharedAccessKey|SharedSecretValue)\\s*=\\s*([^;]{1,100})(?:;|$)");
        regexMap.put("Azure App Configuration Connection String", "(?x)(https://[a-zA-Z0-9-]+\\.azconfig\\.io);Id=([a-zA-Z0-9-]{4}-[a-zA-Z0-9-]{2}-[a-zA-Z0-9-]{2}:[a-zA-Z0-9+/]{18,22});Secret=([a-zA-Z0-9+/]{36,50}=)");
        regexMap.put("Azure Personal Access Token", "(?i:ADO_PAT|pat_token|personal_?access_?token|\\$token)\\s*=\\s*[\"']([a-z0-9]{52})[\"']");
        regexMap.put("Blynk Device Access Token", "https://(?:fra1\\.|lon1\\.|ny3\\.|sgp1\\.|blr1\\.)*blynk\\.cloud/external/api/[a-zA-Z0-9/]*\\?token=([a-zA-Z0-9_\\-]{32})(?:&|$)");
        regexMap.put("Blynk Organization Access Token", "https://(?:fra1\\.|lon1\\.|ny3\\.|sgp1\\.|blr1\\.)*blynk\\.cloud/api/[a-zA-Z0-9_\\-\\s/\\\\]*-H\\s*\"Authorization:\\s*Bearer\\s*([a-zA-Z0-9_\\-]{40})\"");
        regexMap.put("Blynk Organization Client Credentials", "https://(?:fra1\\.|lon1\\.|ny3\\.|sgp1\\.|blr1\\.)*blynk\\.cloud/oauth2/[a-zA-Z0-9_\\-\\s/\\\\?=&]*(?:oa2-client-id_([a-zA-Z0-9_\\-]{32}))(?: : |&client_secret=)([a-zA-Z0-9_\\-]{40})");
        regexMap.put("CodeClimate Reporter ID", "(?:CODECLIMATE_REPO_TOKEN|CC_TEST_REPORTER_ID)\\s*[:=]\\s*([a-f0-9]{64})");
        regexMap.put("Bitbucket App Password", "ATBB[a-zA-Z0-9]{32}");
        regexMap.put("crates.io API Key", "cio[a-zA-Z0-9]{32}");
        regexMap.put("Databricks Personal Access Token", "dapi[a-f0-9]{32}(?:-[0-9]+)?");
        regexMap.put("Dependency-Track API Key", "odt_[A-Za-z0-9]{32,255}");
        regexMap.put("DigitalOcean Application Access Token", "doo_v1_[a-f0-9]{64}");
        regexMap.put("DigitalOcean Personal Access Token", "dop_v1_[a-f0-9]{64}");
        regexMap.put("DigitalOcean Refresh Token", "dor_v1_[a-f0-9]{64}");
        regexMap.put("Django Secret Key", "\\#\\ SECURITY\\ WARNING:\\ keep\\ the\\ secret\\ key\\ used\\ in\\ production\\ secret!\\s*.{0,5}SECRET_KEY\\s*=\\s*r?[\"']([^\"'\\n]{5,100})[\"']");
        regexMap.put("Docker Hub Personal Access Token", "dckr_pat_[a-zA-Z0-9_-]{27}");
        regexMap.put("Facebook Secret Key", "(?:facebook|fb).?(?:api|app|application|client|consumer|customer|secret|key).?(?:key|oauth|sec|secret)?.{0,2}\\s{0,20}.{0,2}\\s{0,20}.{0,2}[a-z0-9]{32}");
        regexMap.put("Facebook Access Token", "EAACEdEose0cBA[a-zA-Z0-9]+");
        regexMap.put("Figma Personal Access Token", "figma.{0,20}\\b([0-9a-f]{4}-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})");
        regexMap.put("GitHub Personal Access Token", "ghp_[a-zA-Z0-9]{36}");
        regexMap.put("GitHub OAuth Access Token", "gho_[a-zA-Z0-9]{36}");
        regexMap.put("GitHub App Token", "(?:ghu|ghs)_[a-zA-Z0-9]{36}");
        regexMap.put("GitHub Refresh Token", "ghr_[a-zA-Z0-9]{76}");
        regexMap.put("GitHub Client ID", "(?:github).?(?:api|app|application|client|consumer|customer)?.?(?:id|identifier|key).{0,2}\\s{0,20}.{0,2}\\s{0,20}.{0,2}[a-z0-9]{20}");
        regexMap.put("GitHub Secret Key", "github.?(?:api|app|application|client|consumer|customer|secret|key).?(?:key|oauth|sec|secret)?.{0,2}\\s{0,20}.{0,2}\\s{0,20}.{0,2}[a-z0-9]{40}");
        regexMap.put("GitHub Personal Access Token (fine-grained permissions)", "github_pat_[0-9a-zA-Z_]{82}");
        regexMap.put("GitLab Runner Registration Token", "GR1348941[0-9a-zA-Z_-]{20}");
        regexMap.put("GitLab Personal Access Token", "glpat-[0-9a-zA-Z_-]{20}");
        regexMap.put("GitLab Pipeline Trigger Token", "glptt-[0-9a-f]{40}");
        regexMap.put("Google Client ID", "[0-9]+-[a-z0-9_]{32}\\.apps\\.googleusercontent\\.com");
        regexMap.put("Google OAuth Client Secret", "GOCSPX-[a-zA-Z0-9_-]{28}");
        regexMap.put("Google OAuth Access Token", "ya29\\.[0-9A-Za-z_-]{20,1024}");
        regexMap.put("Google API Key", "AIza[0-9A-Za-z_-]{35}");
        regexMap.put("Google Cloud Storage Bucket", "(?:^|[\\s/\"']|%2F)((?:[a-zA-Z0-9_-]+\\.)+storage\\.googleapis\\.com)");
        regexMap.put("Google OAuth Credentials", "[0-9]+-[a-z0-9_]{32}\\.apps\\.googleusercontent\\.com)(?:(?s).{0,40})(?:(?i)client.?secret.{0,10})?((?:GOCSPX-[a-zA-Z0-9_-]{28})|(?:\\b[a-zA-Z0-9_-]{24}))");
        regexMap.put("Hardcoded Gradle Credentials", "credentials\\s*\\{(?:\\s*//.*)*\\s*(?:username|password)\\s+['\"]([^'\"]{1,60})['\"](?:\\s*//.*)?(?:\\s*.*\\s*){0,3}\\$mail->Password\\s*=\\s*'([^'\\n]{5,})';");
        regexMap.put("Credentials in PostgreSQL Connection URI", "(?:postgres|postgresql)://([a-zA-Z0-9%;._~!$&'()*+,;=-]{3,}):([a-zA-Z0-9%;._~!$&'()*+,;=-]{3,})@([a-zA-Z0-9_.-]{3,}(?:\\:\\d{1,5})?)");
        regexMap.put("Postman API Key", "PMAK-[a-zA-Z0-9]{24}-[a-zA-Z0-9]{34}");
        regexMap.put("Credentials in PsExec", "psexec.{0,100}-u\\s*(\\S+)\\s+-p\\s*(\\S+)");
        regexMap.put("PyPI Upload Token", "pypi-AgEIcHlwaS5vcmc[a-zA-Z0-9_-]{50,}");
        regexMap.put("React App Username", "REACT_APP(?:_[A-Z0-9]+)*_USER(?:NAME)?\\s*=\\s*['\"]?([^\\s'\"$]{3,})");
        regexMap.put("React App Password", "REACT_APP(?:_[A-Z0-9]+)*_PASS(?:WORD)?\\s*=\\s*['\"]?([^\\s'\"$]{6,})");
        regexMap.put("RubyGems API Key", "rubygems_[a-f0-9]{48}");
        regexMap.put("Salesforce Access Token", "00[a-zA-Z0-9]{13}![a-zA-Z0-9._]{96}");
        regexMap.put("TeamCity API Token", "eyJ0eXAiOiAiVENWMiJ9\\.[A-Za-z0-9_-]{36}\\.[A-Za-z0-9_-]{48}");
        regexMap.put("Telegram Bot Token", "\\d+:AA[a-zA-Z0-9_-]{32,33}");
        regexMap.put("ThingsBoard Access Token", "thingsboard\\.cloud/api/v1/([a-z0-9]{20})");
        regexMap.put("ThingsBoard Provision Device Key", "\"provisionDeviceKey\"\\s*:\\s*\"([a-z0-9]{20})\"");
        regexMap.put("ThingsBoard Provision Device Secret", "\"provisionDeviceSecret\"\\s*:\\s*\"([a-z0-9]{20})\"");
        regexMap.put("TrueNAS API Key (WebSocket)", "\"params\"\\s*:\\s*\\[\\s*\"(\\d+-[a-zA-Z0-9]{64})\"\\s*\\]");
    }


    public static Map<String, String> getRegexMap() {
        return regexMap;
    }

    static class RegexSearchTask implements Callable<Map.Entry<String, List<String>>> {
        private final String regexName;
        private final String regex;
        private final String inputText;

        public RegexSearchTask(String regexName, String regex, String inputText) {
            this.regexName = regexName;
            this.regex = regex;
            this.inputText = inputText;
        }

        @Override
        public Map.Entry<String, List<String>> call() {
            List<String> matches = new ArrayList<>();
            try {
                Pattern pattern = Pattern.compile(regex);
                Matcher matcher = pattern.matcher(inputText);
                while (matcher.find()) {
                    matches.add(matcher.group());
                }
            } catch (PatternSyntaxException e) {
                System.err.println("Invalid regex pattern for " + regexName + ": " + e.getMessage());
            }
            return new AbstractMap.SimpleEntry<>(regexName, matches);
        }
    }
}
