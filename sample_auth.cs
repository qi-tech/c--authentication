using System.Security.Cryptography;
using Jose;
using Newtonsoft.Json;

public class QIToken
{
    static String clientPrivateKey = @"-----BEGIN EC PRIVATE KEY-----
MIHcAgEBBEIBell7txNDr4xYXlDeUO4ySCNRlguHisiC5nUgWDS96j4K2wPksMSA
C6RNmzaz58GPcirbCTHRkpHWhoEaTXO/U4KgBwYFK4EEACOhgYkDgYYABADijSa1
pf3o4QHKevPQ3dEcPqLQLu76K8m0fWo4dYQsaEUou8PbVlvuuMJZyuFbUPSGl+Rz
4DVE3DV1SXrCybyKYgDz2/DKYDLd8aE0YjSfQxkWmOj2Eyvktk3Yk0s/seR4ZhmH
eUhPie2ob0d7QIsC47bqnlAKllL6hPCD7QNZmt1npQ==
-----END EC PRIVATE KEY-----";

    static String qiPublicKey = @"-----BEGIN PUBLIC KEY-----
MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBrhSkDcGyG1u3G47sfe5HW8Wx8egS
2ULxWgZ3aUAIG9p0+G+A7CNpZsrElTC9WQ4BoOFQZQgpqh+uj/Nf9yE14/EBUDoM
hhIek47tcCGBcbHCWsngMv0bSEfw+KRj3deWzopbI5xHj6DJZi5TrgFxF+3/GKMR
7aeiPBNb0lb0rfdNO5Q=
-----END PUBLIC KEY-----";

    static String clientApikey = "97ad0301-869c-4481-98b6-294b139e09ae";
    static String authAddress = "https://api-auth.sandbox.qitech.app";

    static void Main(string[] args){
        MainAsync().Wait();
    }
    static Dictionary<string, string> qiSignHeader(
        string method, 
        string endpoint, 
        string apiKey,
        string privateKey,
        string contentType
    ){
        string md5body = "";
        string now = DateTime.UtcNow.ToString("r");
        string signedString = method + "\n" + md5body + "\n" + contentType + "\n" + now + "\n" + endpoint;
        var payload = new Dictionary<string, string>()
        {       
            {"sub", apiKey },
            {"signature", signedString }            
        };
        var token = Encrypt(privateKey, payload);
        var authorization = "QIT" + " " + apiKey + ":" + token;

        var header = new Dictionary<string, string>()
        {       
            {"AUTHORIZATION", authorization },
            {"API-CLIENT-KEY", apiKey }            
        };
        return header;
    }


    static async Task MainAsync(){
        String endpoint = "/test/" + clientApikey;
        String url = authAddress + endpoint;
        var headers = qiSignHeader(
            "GET",
            endpoint,
            clientApikey,
            clientPrivateKey,
            ""
        );
        var client = new HttpClient();
        var httpRequestMessage = new HttpRequestMessage
            {
                Method = HttpMethod.Get,
                RequestUri = new Uri(url)
            };
        foreach (KeyValuePair<string, string> kvp in headers)
        {
            Console.WriteLine("-----------------------------");
            Console.WriteLine("Key = {0}, Value = {1}", kvp.Key, kvp.Value);
            httpRequestMessage.Headers.Add(kvp.Key, kvp.Value);
        }        

        var response = client.SendAsync(httpRequestMessage).Result;
        string damn = await response.Content.ReadAsStringAsync();
        Dictionary<string, string> values = JsonConvert.DeserializeObject<Dictionary<string, string>>(damn);
        var encodedResponse = values["encoded_body"];
        var decriptedResponse = Decrypt(qiPublicKey, encodedResponse);
        Console.WriteLine(decriptedResponse);
    }

    public static string Decrypt(string clientPublicKey, string value)
    {
        var key = ECDsa.Create();
        key.ImportFromPem(clientPublicKey);
        var json = Jose.JWT.Decode(value, key, JwsAlgorithm.ES512);

        return json;
    }

    public static string Encrypt(string apiPrivateKey, Dictionary<string, string> value)
    {
        var key = ECDsa.Create();
        key.ImportFromPem(apiPrivateKey);
        var token = Jose.JWT.Encode(value, key, JwsAlgorithm.ES512);
        return token;
    }
}
