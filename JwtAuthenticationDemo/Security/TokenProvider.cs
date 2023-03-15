using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;
using System.Text;
using System;
using System.Collections.Generic;

namespace JwtAuthenticationDemo.Security
{
    public interface ITokenProvider
    {
        string CreateToken(IPrincipal principal, bool rememberMe);

    }

    public class TokenProvider : ITokenProvider
    {
        private const string AuthoritiesKey = "auth";

        private readonly SecuritySettings _securitySettings;

        private readonly JwtSecurityTokenHandler _jwtSecurityTokenHandler;

        private readonly ILogger<TokenProvider> _log;

        private SigningCredentials _key;

        private long _tokenValidityInSeconds;

        private long _tokenValidityInSecondsForRememberMe;


        public TokenProvider(ILogger<TokenProvider> log, IOptions<SecuritySettings> securitySettings)
        {
            _log = log;
            _securitySettings = securitySettings.Value;
            _jwtSecurityTokenHandler = new JwtSecurityTokenHandler();
            Init();
        }

        public string CreateToken(IPrincipal principal, bool rememberMe)
        {
            var subject = CreateSubject(principal);
            var validity =
                DateTime.UtcNow.AddSeconds(rememberMe
                    ? _tokenValidityInSecondsForRememberMe
                    : _tokenValidityInSeconds);

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = subject,
                Expires = validity,
                SigningCredentials = _key
            };

            var token = _jwtSecurityTokenHandler.CreateToken(tokenDescriptor);
            return _jwtSecurityTokenHandler.WriteToken(token);
        }

        private void Init()
        {
            byte[] keyBytes;
            var secret = _securitySettings.Authentication.Jwt.Secret;

            if (!string.IsNullOrWhiteSpace(secret))
            {
                _log.LogWarning("Warning: the JWT key used is not Base64-encoded. " +
                                "We recommend using the `security.authentication.jwt.base64-secret` key for optimum security.");
                keyBytes = Encoding.ASCII.GetBytes(secret);
            }
            else
            {
                _log.LogDebug("Using a Base64-encoded JWT secret key");
                keyBytes = Encoding.UTF8.GetBytes(_securitySettings.Authentication.Jwt.Base64Secret);
            }

            _key = new SigningCredentials(new SymmetricSecurityKey(keyBytes), SecurityAlgorithms.HmacSha256);
            _tokenValidityInSeconds = _securitySettings.Authentication.Jwt.TokenValidityInSeconds;
            _tokenValidityInSecondsForRememberMe =_securitySettings.Authentication.Jwt.TokenValidityInSecondsForRememberMe;
        }

        private static ClaimsIdentity CreateSubject(IPrincipal principal)
        {
            var username = principal.Identity.Name??"Test";
            var roles = GetRoles(principal);
            var authValue = "User";// string.Join(",", roles.Select(it => it.Value));
            return new ClaimsIdentity(new[] {
            new Claim(JwtRegisteredClaimNames.Sub, username),
            new Claim(AuthoritiesKey, authValue)
        });
        }

        private static IEnumerable<Claim> GetRoles(IPrincipal principal)
        {
            return principal is ClaimsPrincipal user
                ? user.FindAll(it => it.Type == ClaimTypes.Role)
                : Enumerable.Empty<Claim>();
        }
    }
}
