using System.Security.Claims;
using System.Text;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;

namespace SecureTokenHome
{
    public class SecretTokenHelper
    {
        public static string Issuer { get; private set; } = "SampleJwtWebApp";
        public static string[] Audiences { get; private set; } = new string[] { "SampleJwtWebApp" };

        public static string ServerBearer = "S";

        public static string GetUserToken()
        {
            var signingKey = new SymmetricSecurityKey(GetClientSecretKey());

            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, "userId"),
                new Claim(ClaimTypes.Role, "User"),
            };
            AddAud(claims);

            var jwtSecurityToken = new JwtSecurityToken(
                issuer: Issuer,
                claims: claims,
                expires: DateTime.Now.AddDays(1),
                signingCredentials: new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha512)
            );

            return new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken);
        }
        public static byte[] GetClientSecretKey()
        {
            var bytes = Encoding.UTF8.GetBytes("askjdhf98hjll6yughljasdf9h25khns;lzdfh98sddfbu;12kjaiodhjgo;aihew4t-89q34nop;asdok;fg");
            Array.Resize(ref bytes, 64);
            return bytes;
        }

        public static string GetServerToken()
        {
            var signingKey = new SymmetricSecurityKey(GetServerSecretKey());

            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, "serverId"),
                new Claim(ClaimTypes.Role, "Server"),
            };
            AddAud(claims);

            var jwtSecurityToken = new JwtSecurityToken(
                issuer: Issuer,
                claims: claims,
                expires: DateTime.Now.AddSeconds(5),
                signingCredentials: new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha512)
            );
            return new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken);
        }
        public static byte[] GetServerSecretKey()
        {
            var bytes = Encoding.UTF8.GetBytes("askjdhasdgasdgaga2b52qbsdg5khns;lzdfh98sddfbu;12kjaiodhjgo;aihew4t-89q34nop;asdok;fg");
            Array.Resize(ref bytes, 64);
            return bytes;
        }
        private static void AddAud(List<Claim> claims)
        {
            foreach (var audience in Audiences)
            {
                claims.Add(new Claim(JwtRegisteredClaimNames.Aud, audience));
            }
        }
    }
}