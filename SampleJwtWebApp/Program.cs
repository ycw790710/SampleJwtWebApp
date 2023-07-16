using IntegrateAuthNameSpace;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using SampleJwtWebApp.Auths;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace SampleJwtWebApp
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            builder.Services.AddControllers();
            builder.Services
                .AddGrpcClient<IntegrateAuthGrpcService.IntegrateAuthGrpcServiceClient>(options =>
                {
                    options.Address = new Uri("https://localhost:7256");
                })
                .AddCallCredentials((context, metadata) =>
                {
                    metadata.Add("Authorization", $"Bearer {GetServerToken()}");
                    return Task.CompletedTask;
                });
            builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddScheme<AuthenticationSchemeOptions, TokenAuthenticationHandler>(JwtBearerDefaults.AuthenticationScheme, options => { });
            builder.Services.AddAuthorization();

            builder.Services.AddEndpointsApiExplorer();
            builder.Services.AddSwaggerGen(c =>
            {
                c.SwaggerDoc("v1", new OpenApiInfo { Title = "SampleJwtWebApp Api", Version = "v1" });
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


            app.MapControllers();

            app.Run();
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

        static string GetServerToken()
        {
            var signingKey = new SymmetricSecurityKey(Program.GetSecretKey());

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
        public static byte[] GetSecretKey()
        {
            var bytes = Encoding.UTF8.GetBytes("askjdhf98asdf9h25khns;lzdfh98sddfbu;12kjaiodhjgo;aihew4t-89q34nop;asdok;fg");
            Array.Resize(ref bytes, 64);
            return bytes;
        }

    }
}