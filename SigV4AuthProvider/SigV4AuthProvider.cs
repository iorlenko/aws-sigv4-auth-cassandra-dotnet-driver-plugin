using System.Net;
using Amazon.Runtime;
using Cassandra;

namespace SigV4AuthProvider;

public class SigV4AuthProvider : IAuthProvider
{
    private readonly AWSCredentials _credentials;
    private readonly string _region;

    public SigV4AuthProvider(string region)
        : this(FallbackCredentialsFactory.GetCredentials(), region)
    {
    }

    public SigV4AuthProvider(AWSCredentials credentials, string region)
    {
        _credentials = credentials;
        _region = region;
    }
    
    public IAuthenticator NewAuthenticator(IPEndPoint host)
    {
        return new SigV4Authenticator(_credentials, _region);
    }
}