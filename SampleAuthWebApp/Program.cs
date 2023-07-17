using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Net.Http.Headers;
using Microsoft.OpenApi.Models;
using SampleAuthWebApp.Auths;
using SampleAuthWebApp.Services;
using SecureTokenHome;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace SampleAuthWebApp
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            // Add services to the container.

            builder.Services.AddControllers();
            builder.Services.AddGrpc();

            builder.Services.AddAuthentication(options =>
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
            builder.Services.AddAuthorization();

            // Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
            builder.Services.AddEndpointsApiExplorer();
            builder.Services.AddSwaggerGen(c =>
            {
                c.SwaggerDoc("v1", new OpenApiInfo { Title = "SampleAuthWebApp Api", Version = "v1" });
                c.AddSecurityDefinition(JwtBearerDefaults.AuthenticationScheme, new OpenApiSecurityScheme
                {
                    Description = $"\"Authorization: {JwtBearerDefaults.AuthenticationScheme} {{token}}\" or \"Authorization: {SecureTokenHelper.ServerBearer} {{token}}\"",
                    Name = HeaderNames.Authorization,
                    In = ParameterLocation.Header,
                    Type = SecuritySchemeType.ApiKey,
                    Scheme = JwtBearerDefaults.AuthenticationScheme
                });
                c.AddSecurityRequirement(new OpenApiSecurityRequirement
            {
                {
                    new OpenApiSecurityScheme
                    {
                        Reference = new OpenApiReference
                        {
                            Type = ReferenceType.SecurityScheme,
                            Id = "Bearer"
                        }
                    },
                    new string[] {}
                }
            });
            });

            var app = builder.Build();

            // Configure the HTTP request pipeline.
            if (app.Environment.IsDevelopment())
            {
                app.UseSwagger();
                app.UseSwaggerUI();
            }

            app.UseHttpsRedirection();

            app.UseAuthentication();
            app.UseAuthorization();

            app.MapGrpcService<AuthService>();
            app.MapControllers();

            app.Run();
        }


    }
}