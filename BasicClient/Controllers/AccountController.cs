using BasicClient.Models;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;

namespace BasicClient.Controllers
{
    public class AccountController : Controller
    {
        public ActionResult Login()
        {
            var state = Guid.NewGuid().ToString("N");
            var nonce = Guid.NewGuid().ToString("N");

            var url = Configuration.AuthorizeEndpoint +
                "?client_id=" + Configuration.ClientId +
                "&response_type=code" +
                "&scope=openid profile" +
                "&redirect_uri=" + Configuration.CallbackEndpoint +
                "&state=" + state +
                "&nonce=" + nonce;

            SetTempState(new TempState { State = state, Nonce = nonce });
            return Redirect(url);
        }

        public async Task<ActionResult> Callback(string code, string state, string error)
        {
            // retrieve and cleanup temp state
            var tempState = await GetTempStateAsync();

            // check if OP returned an error
            if (!string.IsNullOrWhiteSpace(error))
            {
                ViewBag.Error = error;
                return View("Error");
            }

            // check that required params are present
            if (string.IsNullOrWhiteSpace(code) || string.IsNullOrWhiteSpace(state))
            {
                ViewBag.Error = "Invalid response.";
                return View("Error");
            }

            // check state parameter
            if (!state.Equals(tempState.State, StringComparison.Ordinal))
            {
                ViewBag.Error = "Invalid response.";
                return View("Error");
            }

            // call token endpoint and redeem code
            var tokenResponse = await GetTokenResponseAsync(code);
            if (tokenResponse.IsError)
            {
                ViewBag.Error = tokenResponse.Error;
                return View("Error");
            }

            // validate identity token
            ValidateTokenResponse(tokenResponse, tempState);

            // call userinfo endpoint to get claims for user
            var userInfo = await GetUserInfoClaims(tokenResponse.AccessToken);

            // create cookie and sign-in user
            var id = new ClaimsIdentity(userInfo.Claims, "Cookies");
            id.AddClaim(new Claim("id_token", tokenResponse.IdentityToken));

            Request.GetOwinContext().Authentication.SignIn(id);

            return Redirect("/");
        }

        private async Task<UserInfoResult> GetUserInfoClaims(string token)
        {
            var client = new HttpClient();
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

            var result = await client.GetAsync(Configuration.UserInfoEndpoint);
            if (result.StatusCode != HttpStatusCode.OK)
            {
                return new UserInfoResult
                {
                    IsError = true,
                    Error = result.ReasonPhrase
                };
            }

            var json = await result.Content.ReadAsStringAsync();
            var userInfo = JsonConvert.DeserializeObject<Dictionary<string, object>>(json);

            var claims = new List<Claim>();

            foreach (var item in userInfo)
            {
                var values = item.Value as IEnumerable<object>;

                if (values == null)
                {
                    claims.Add(new Claim(item.Key, item.Value.ToString()));
                }
                else
                {
                    foreach (var value in values)
                    {
                        claims.Add(new Claim(item.Key, value.ToString()));
                    }
                }
            }

            return new UserInfoResult
            {
                Claims = claims
            };
        }

        private ValidationResult ValidateTokenResponse(TokenResponse tokenResponse, TempState tempState)
        {
            var validation = new TokenValidationParameters
            {
                ValidAudience = Configuration.ClientId,
                ValidIssuer = Configuration.IssuerName,
                IssuerSigningToken = new X509SecurityToken(Configuration.SigningCert)
            };

            var handler = new JwtSecurityTokenHandler();
            SecurityToken token;
            var principal = handler.ValidateToken(tokenResponse.IdentityToken, validation, out token);

            var nonceClaim = principal.FindFirst("nonce");
            if (nonceClaim == null)
            {
                return new ValidationResult
                {
                    IsError = true,
                    Error = "Nonce claim is missing"
                };
            }

            if (!string.Equals(nonceClaim.Value, tempState.Nonce, StringComparison.Ordinal))
            {
                return new ValidationResult
                {
                    IsError = true,
                    Error = "Invalid nonce"
                };
            }

            return new ValidationResult();
        }

        private async Task<TokenResponse> GetTokenResponseAsync(string code)
        {
            var client = new HttpClient();

            var form = new Dictionary<string, string>
            {
                { "grant_type", "authorization_code" },
                { "code", code },
                { "redirect_uri", Configuration.CallbackEndpoint },
                { "client_id", Configuration.ClientId },
                { "client_secret", Configuration.ClientSecret }
            };

            var response = await client.PostAsync(Configuration.TokenEndpoint, new FormUrlEncodedContent(form));
            if (response.StatusCode != HttpStatusCode.OK)
            {
                return new TokenResponse
                {
                    IsError = true,
                    Error = response.ReasonPhrase
                };
            }

            var json = JObject.Parse(await response.Content.ReadAsStringAsync());

            return new TokenResponse
            {
                IdentityToken = json["id_token"].ToString(),
                AccessToken = json["access_token"].ToString()
            };
        }

        public ActionResult Logout()
        {
            Request.GetOwinContext().Authentication.SignOut();
            return Redirect(Configuration.EndSessionEndpoint);
        }

        private void SetTempState(TempState temp)
        {
            var tempId = new ClaimsIdentity("TempCookie");
            tempId.AddClaim(new Claim("state", temp.State));
            tempId.AddClaim(new Claim("nonce", temp.Nonce));

            Request.GetOwinContext().Authentication.SignIn(tempId);
        }

        private async Task<TempState> GetTempStateAsync()
        {
            var owin = Request.GetOwinContext();

            var temp = await owin.Authentication.AuthenticateAsync("TempCookie");
            owin.Authentication.SignOut("TempCookie");

            return new TempState
            {
                State = temp.Identity.FindFirst("state").Value,
                Nonce = temp.Identity.FindFirst("nonce").Value
            };
        }
    }
}