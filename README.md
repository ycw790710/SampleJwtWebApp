# SampleJwtWebApp

## 將 Jwt Token 轉發給 Auth Web Api驗證
### 透過TokenAuthenticationHandler, 並使用Grpc轉發
```
protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
{
    if (!Request.Headers.ContainsKey(HeaderNames.Authorization))
    {
        return AuthenticateResult.Fail("Missing or invalid Authorization header.");
    }
    string token = Request.Headers[HeaderNames.Authorization].ToString();
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
```
### 在Auth Web Api的Grpc Service的驗證
```
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
```
### 區分 User的Jwt Token 和Server Api使用的Jwt Token
```
builder.Services
    .AddAuthentication(options =>
    {
        options.DefaultScheme = "User_Or_Server";
        options.DefaultChallengeScheme = "User_Or_Server";
    })
    .AddPolicyScheme("User_Or_Server", "User_Or_Server", options =>
    {
        options.ForwardDefaultSelector = context =>
        {
            string authorization = context.Request.Headers[HeaderNames.Authorization];
            if (!string.IsNullOrEmpty(authorization) && authorization.StartsWith(SecureTokenHelper.ServerBearer))
            {
                return SecureTokenHelper.ServerBearer;
            }
            return JwtBearerDefaults.AuthenticationScheme;
        };
    })
    .AddJwtBearer(JwtBearerDefaults.AuthenticationScheme, JwtBearerDefaults.AuthenticationScheme, options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = SecureTokenHelper.Issuer,
            ValidAudiences = SecureTokenHelper.Audiences,
            IssuerSigningKeyResolver = (string unvalidToken, SecurityToken securityToken, string kid, TokenValidationParameters validationParameters) =>
            {
               return new[] { new SymmetricSecurityKey(SecureTokenHelper.GetClientSecretKey()) };
            },
            ClockSkew = TimeSpan.Zero
        };
    })
    .AddScheme<JwtBearerOptions, ServerTokenAuthenticationHandler2>(SecureTokenHelper.ServerBearer, SecureTokenHelper.ServerBearer, options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
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
    });
```

### validate token client call server 測試
![測試](sample.png)
