using IntegrateAuthNameSpace;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using System.Security.Claims;
using System.Text.Encodings.Web;

namespace SampleJwtWebApp.Auths
{
    public class TokenAuthenticationHandler : AuthenticationHandler<AuthenticationSchemeOptions>
    {
        private readonly IntegrateAuthGrpcService.IntegrateAuthGrpcServiceClient _integrateAuthGrpcServiceClient;

        public TokenAuthenticationHandler(IOptionsMonitor<AuthenticationSchemeOptions> options,
            ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock,
            IntegrateAuthGrpcService.IntegrateAuthGrpcServiceClient integrateAuthGrpcServiceClient)
            : base(options, logger, encoder, clock)
        {
            _integrateAuthGrpcServiceClient = integrateAuthGrpcServiceClient;
        }

        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            if (!Request.Headers.ContainsKey("Authorization"))
            {
                return AuthenticateResult.Fail("Missing or invalid Authorization header.");
            }

            string token = Request.Headers["Authorization"].ToString();

            var reply = await _integrateAuthGrpcServiceClient.ValidateTokenAsync(new ValidateTokenRequest()
            {
                UserToken = token
            });
            if (!reply.Valid)
            {
                return AuthenticateResult.Fail("Token validation failed.");
            }

            List<Claim> claims = new();
            foreach (var claim in reply.Claims)
            {
                claims.Add(new Claim(claim.Key, claim.Value, claim.ValueType));
            }

            var identity = new ClaimsIdentity(claims, Scheme.Name);
            var principal = new ClaimsPrincipal(identity);
            var ticket = new AuthenticationTicket(principal, Scheme.Name);

            return AuthenticateResult.Success(ticket);
        }

    }

}
