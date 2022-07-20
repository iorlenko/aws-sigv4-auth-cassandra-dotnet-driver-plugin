using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using Amazon.Runtime;
using Amazon.Util;
using Cassandra;

namespace SigV4AuthProvider;

public class SigV4Authenticator: IAuthenticator
{
    private readonly AWSCredentials _credentials;
    private readonly string _region;
    private static readonly byte[] InitBuffer = Encoding.UTF8.GetBytes("SigV4\0\0");
    private static readonly string ISO8601Format = "yyyy-MM-ddTHH\\:mm\\:ss.fffZ";
    private static readonly string DateStringFormat = "yyyyMMdd";
    private static readonly string HMACSHA256 = "HMACSHA256";
    private static readonly string CANONICAL_SERVICE = "cassandra";
    private static readonly string TERMINATOR = "aws4_request";
    private static readonly string SCHEME = "AWS4";
    private static readonly string ALGORITHM = "HMAC-SHA256";
    private static readonly HashAlgorithm CanonicalHashAlgorithm = HashAlgorithm.Create("SHA-256");
    
    private static readonly string Aws4SigningAlgorithm = $"{SCHEME}-{ALGORITHM}";
    private static readonly string AmzAlgoHeader = "X-Amz-Algorithm=" + Aws4SigningAlgorithm;
    private static readonly string AmzExpiresHeader = "X-Amz-Expires=900";
    

    public SigV4Authenticator(AWSCredentials credentials, string region)
    {
        _credentials = credentials;
        _region = region;
    }

    public byte[] InitialResponse()
    {
        return InitBuffer;
    }

    public byte[] EvaluateChallenge(byte[] challenge)
    {
        var nonce = ExtractNonce(challenge);

        var date = DateTime.UtcNow;

        var credentials = _credentials.GetCredentials();
        return ComputeSigV4SignatureCassandraRequest(_region, nonce, date,
            credentials.AccessKey,
            credentials.SecretKey,
            credentials.Token);
    }

    private string ExtractNonce(byte[] challenge)
    {
        string challengeStr = System.Text.Encoding.UTF8.GetString(challenge);
        var res1 = challengeStr.Split("nonce=");

        if (res1.Length < 2)
        {
            throw new ArgumentException("Nonce is not found");
        }

        var res2 = res1[1].Split(',');

        return res2[0];
    }

    private byte[] ComputeSigV4SignatureCassandraRequest(
        string region,
        string nonce,
        DateTime date,
        string accessKey,
        string secretAccessKey,
        string sessionToken
    )
    {
        var dateTimeStamp = date.ToString(ISO8601Format, CultureInfo.InvariantCulture);
        var dateStamp = date.ToString(DateStringFormat, CultureInfo.InvariantCulture);
        
        var scope = string.Format("{0}/{1}/{2}/{3}",
            dateStamp,
            region,
            CANONICAL_SERVICE,
            TERMINATOR);

        var nonceHash = CanonicalHashAlgorithm.ComputeHash(Encoding.UTF8.GetBytes(nonce));
        var nonceHashString = AWSSDKUtils.ToHex(nonceHash, true);
        var canonicalRequest = CanonicalizeRequest(accessKey, scope, dateTimeStamp, nonceHashString);
        byte[] canonicalRequestHashBytes 
            = CanonicalHashAlgorithm.ComputeHash(Encoding.UTF8.GetBytes(canonicalRequest));
        
        // construct the string to be signed
        string stringToSign =
            $"{Aws4SigningAlgorithm}\n{dateTimeStamp}\n{scope}\n{AWSSDKUtils.ToHex(canonicalRequestHashBytes, true)}";
        
        // compute the multi-stage signing key
        var signingKey = DeriveSigningKey(HMACSHA256, secretAccessKey, region, dateStamp, CANONICAL_SERVICE);
        
        var signature = ComputeKeyedHash(HMACSHA256, signingKey, Encoding.UTF8.GetBytes(stringToSign));
        
        var signatureString = AWSSDKUtils.ToHex(signature, true);
     
        var result = $"signature={signatureString},access_key={accessKey},amzdate={dateTimeStamp}";

        if (!string.IsNullOrEmpty(sessionToken)) {
            result += $",session_token={sessionToken}";
        }

        return Encoding.UTF8.GetBytes(result);
    }
    
    private byte[] DeriveSigningKey(string algorithm, string awsSecretAccessKey, string region, string date, string service)
    {
        string ksecret = SCHEME + awsSecretAccessKey;

        byte[] hashDate = ComputeKeyedHash(algorithm, Encoding.UTF8.GetBytes(ksecret), Encoding.UTF8.GetBytes(date));
        byte[] hashRegion = ComputeKeyedHash(algorithm, hashDate, Encoding.UTF8.GetBytes(region));
        byte[] hashService = ComputeKeyedHash(algorithm, hashRegion, Encoding.UTF8.GetBytes(service));
        return ComputeKeyedHash(algorithm, hashService, Encoding.UTF8.GetBytes(TERMINATOR));
    }
    
    private byte[] ComputeKeyedHash(string algorithm, byte[] key, byte[] data)
    {
        using var kha = KeyedHashAlgorithm.Create(algorithm);
        kha.Key = key;
        return kha.ComputeHash(data);
    }

    private static string CanonicalizeRequest(String accessKey,
        String signingScope,
        string requestTimestamp,
        String payloadHash)
    {
        List<String> queryStringHeaders = new List<string>
        {
            AmzAlgoHeader,
            $"X-Amz-Credential={accessKey}%2F{UrlEncoder.Default.Encode(signingScope)}",
            "X-Amz-Date=" + UrlEncoder.Default.Encode(requestTimestamp),
            AmzExpiresHeader
        };

        // IMPORTANT: This list must maintain alphabetical order for canonicalization
        queryStringHeaders.Sort(StringComparer.Ordinal);
        
        String queryString = String.Join("&", queryStringHeaders);

        return $"PUT\n/authenticate\n{queryString}\nhost:{CANONICAL_SERVICE}\n\nhost\n{payloadHash}";
    }
}