using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using SampleAuthWebApp.Services;
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

            builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
           .AddJwtBearer(options =>
           {
               options.TokenValidationParameters = new TokenValidationParameters
               {
                   ValidateIssuer = true,
                   ValidateAudience = true,
                   ValidateLifetime = true,
                   ValidateIssuerSigningKey = true,
                   ValidIssuer = "https://localhost:7256",
                   ValidAudiences = new string[] { "https://localhost:7256", "https://localhost:7136" },
                   IssuerSigningKeyResolver = (string unvalidToken, SecurityToken securityToken, string kid, TokenValidationParameters validationParameters) =>
                   {
                       return new[] { new SymmetricSecurityKey(GetSecretKey()) };
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
                c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
                {
                    Description = "JWT Authorization header using the Bearer scheme. Example: \"Authorization: Bearer {token}\"",
                    Name = "Authorization",
                    In = ParameterLocation.Header,
                    Type = SecuritySchemeType.ApiKey,
                    Scheme = "Bearer"
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

        public static byte[] GetSecretKey()
        {
            var bytes = Encoding.UTF8.GetBytes("askjdhf98asdf9h25khns;lzdfh98sddfbu;12kjaiodhjgo;aihew4t-89q34nop;asdok;fg");
            Array.Resize(ref bytes, 64);
            return bytes;
        }

        public static string GetUserToken()
        {
            var signingKey = new SymmetricSecurityKey(GetSecretKey());

            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, "userId"),
                new Claim(ClaimTypes.Role, "User"),
            };
            AddAud(claims);

            return CreateToken(signingKey, claims);
        }

        private static string CreateToken(SymmetricSecurityKey signingKey, List<Claim> claims)
        {
            var jwtSecurityToken = new JwtSecurityToken(
                issuer: "https://localhost:7256",
                claims: claims,
                expires: DateTime.Now.AddDays(1),
                signingCredentials: new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha512)
            );

            return new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken);
        }

        public static string GetServerToken()
        {
            var signingKey = new SymmetricSecurityKey(GetSecretKey());

            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, "serverId"),
                new Claim(ClaimTypes.Role, "Server"),
            };
            AddAud(claims);

            return CreateToken(signingKey, claims);
        }
        private static void AddAud(List<Claim> claims)
        {
            claims.Add(new Claim(JwtRegisteredClaimNames.Aud, "https://localhost:7256"));
            claims.Add(new Claim(JwtRegisteredClaimNames.Aud, "https://localhost:7136"));
        }

    }
}