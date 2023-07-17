using Grpc.Core;
using IntegrateAuthNameSpace;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Net.Http.Headers;

namespace SampleAuthWebApp.Services
{
    [Authorize(Roles = "Server")]
    public class AuthService : IntegrateAuthGrpcService.IntegrateAuthGrpcServiceBase
    {
        private readonly IServiceScopeFactory _serviceScopeFactory;

        public AuthService(IServiceScopeFactory serviceScopeFactory)
        {
            _serviceScopeFactory = serviceScopeFactory;
        }

        public override async Task<ValidateTokenReply> ValidateToken(ValidateTokenRequest request, ServerCallContext context)
        {
            var userToken = request.UserToken;

            var httpContext = new DefaultHttpContext();
            httpContext.Request.Headers.Add(HeaderNames.Authorization, userToken);
            httpContext.ServiceScopeFactory = _serviceScopeFactory;
            var authenticateResult = await httpContext.AuthenticateAsync(JwtBearerDefaults.AuthenticationScheme);

            var validateTokenReply = new ValidateTokenReply();
            if (authenticateResult.Succeeded)
            {
                var claims = authenticateResult.Principal.Claims;
                foreach (var claim in claims)
                {
                    validateTokenReply.Claims.Add(new ValidateTokenClaimItem()
                    {
                        Key = claim.Type,
                        Value = claim.Value,
                        ValueType = claim.ValueType
                    });
                }
                validateTokenReply.Valid = true;
            }
            else
            {
                validateTokenReply.Valid = false;
            }
            return validateTokenReply;
        }
    }
}
