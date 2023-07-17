using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Net.Http.Headers;
using SecureTokenHome;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text.Encodings.Web;

namespace SampleAuthWebApp.Auths
{
    public class ServerTokenAuthenticationHandler : AuthenticationHandler<AuthenticationSchemeOptions>
    {
        public ServerTokenAuthenticationHandler(IOptionsMonitor<AuthenticationSchemeOptions> options,
            ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock)
            : base(options, logger, encoder, clock)
        {
        }

        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            if (!Request.Headers.ContainsKey(HeaderNames.Authorization))
            {
                return AuthenticateResult.Fail("Missing or invalid Authorization header.");
            }

            string token = Request.Headers[HeaderNames.Authorization].ToString().Substring(SecureTokenHelper.ServerBearer.Length).TrimStart();

            if (!ValidateToken(token))
            {
                return AuthenticateResult.Fail("Token validation failed.");
            }

            var claims = GetClaimsFromToken(token);

            var identity = new ClaimsIdentity(claims, Scheme.Name);
            var principal = new ClaimsPrincipal(identity);
            var ticket = new AuthenticationTicket(principal, Scheme.Name);

            return AuthenticateResult.Success(ticket);
        }
        public static IEnumerable<Claim>? GetClaimsFromToken(string token)
        {
            var handler = new JwtSecurityTokenHandler();
            var jwtSecurityToken = handler.ReadToken(token) as JwtSecurityToken;
            return jwtSecurityToken?.Claims;
        }

        private static bool ValidateToken(string token)
        {
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                ValidIssuer = SecureTokenHelper.Issuer,
                ValidAudiences = SecureTokenHelper.Audiences,
                IssuerSigningKeyResolver = (string unvalidToken, SecurityToken securityToken, string kid, TokenValidationParameters validationParameters) =>
                {
                    return new[] { new SymmetricSecurityKey(SecureTokenHelper.GetServerSecretKey()) };
                },
                ClockSkew = TimeSpan.Zero
            };

            var tokenHandler = new JwtSecurityTokenHandler();

            try
            {
                var claimsPrincipal = tokenHandler.ValidateToken(token, tokenValidationParameters, out _);
                return claimsPrincipal.Identity.IsAuthenticated;
            }
            catch
            {
                return false;
            }
        }
    }
}
