using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.Azure.WebJobs.Host;

namespace FunctionTokenTest
{
    public static class TokenTest1
    {
        [FunctionName("TokenTest")]
        public static async Task<HttpResponseMessage> Run([HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = null)]HttpRequestMessage req, TraceWriter log)
        {
            if (!req.Headers.Contains("Authorization"))
            {
                return new HttpResponseMessage(HttpStatusCode.Forbidden);
            }

            var headerValue = req.Headers.GetValues("Authorization");
            var bearerValue = headerValue.FirstOrDefault(v => v.StartsWith("Bearer"));
            var bearerToken = bearerValue.Split(' ')[1];

            var principal = ValidateToken(bearerToken, "MYISSUER", "MYSCOPE");
            if (principal == null)
            {
                return new HttpResponseMessage(HttpStatusCode.Forbidden);
            }

            return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent($"Hello {principal.Identity.Name}") };
        }

        private static ClaimsPrincipal ValidateToken(string jwtToken, string issuer, string requiredScope)
        {
            var handler = new JwtSecurityTokenHandler();
            if (!handler.CanReadToken(jwtToken))
            {
                return null;
            }

            handler.InboundClaimTypeMap.Clear();

            Microsoft.IdentityModel.Tokens.SecurityToken token;
            var principal = handler.ValidateToken(jwtToken, new Microsoft.IdentityModel.Tokens.TokenValidationParameters()
            {
                ValidateAudience = false,
                ValidIssuer = issuer,
                ValidateIssuerSigningKey = false,
                SignatureValidator = (t, param) => new JwtSecurityToken(t),
                NameClaimType = "sub"

            }, out token);

            if (!principal.Claims.Any(c => c.Type == "scope" && c.Value == requiredScope))
            {
                return null;
            }

            return principal;
        }
    }
}