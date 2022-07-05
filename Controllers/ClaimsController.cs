using IdentityModel.Client;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Newtonsoft.Json.Linq;
using System;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.AspNetCore.Cors;

namespace MvcCode.Controllers
{
    public class AutenticacionDigital
    {
        public string sub { get; set; }
        public string auth_time { get; set; }
        public string idp { get; set; }
        public string acr { get; set; }
        public string name { get; set; }
        public string s_hash { get; set; }
        public string Identificacion { get; set; }
        public string TipoIdentificacion { get; set; }
        public string LOA { get; set; }
        public string PrimerNombre { get; set; }
        public string SegundoNombre { get; set; }
        public string PrimerApellido { get; set; }
        public string SegundoApellido { get; set; }
        public string nickname { get; set; }
        public string Telefono { get; set; }
        public string Direccion { get; set; }
        public string DireccionJSON { get; set; }
        public string preferred_username { get; set; }
        public string email { get; set; }
        public string email_verified { get; set; }
        public string amr { get; set; }
    }
    public class ClaimsController : Controller
    {
        private readonly IConfiguration _configuration;       
        private readonly IMemoryCache _cache;
        public ClaimsController(IConfiguration _config, IMemoryCache cache)
        {
            _configuration = _config;
            _cache = cache;
        }
        public async Task<IActionResult> IndexAsync()
        {
            var httpClient = new HttpClient();
            var userInfo = new UserInfoRequest();
            /*
             //You get the user's first and last name below:
            ViewBag.Name = userClaims?.FindFirst("audd")?.Value;

            // The 'preferred_username' claim can be used for showing the username
            ViewBag.Username = userClaims?.FindFirst("audd")?.Value;

            // The subject/ NameIdentifier claim can be used to uniquely identify the user across the web
            ViewBag.Subject = userClaims?.FindFirst("sub")?.Value;

            // TenantId is the unique Tenant Id - which represents an organization in Azure AD
            ViewBag.TenantId = userClaims?.FindFirst("isss")?.Value;
            string authority = _configuration.GetValue<string>(
               "ServerSettings:authority");
            userInfo.Address = authority + "/connect/userinfo";
            userInfo.Token = userClaims?.FindFirst("access_token")?.Value;

            var userInfoProfile = await httpClient.GetUserInfoAsync(userInfo);
            */
            var userClaims = User.Identity as System.Security.Claims.ClaimsIdentity;

            ViewBag.userClaims = userClaims.Claims;
           
            return View();
        }

        [EnableCors("PermitirApiRequest")]
        [AllowAnonymous]
        //[HttpGet("GetClaims/{guid}")]
        public async Task<IActionResult> GetClaims(string guid) {
            if(!string.IsNullOrWhiteSpace(guid)){
                
            AutenticacionDigital c;
            if(_cache.TryGetValue(guid, out c)){
                return Json(c);
            }
        }
            if (!User.Identity!.IsAuthenticated)
                return Json(new object());
            var userClaims = User.Identity as System.Security.Claims.ClaimsIdentity;

            ViewBag.userClaims = userClaims.Claims;
           
            //var userInfoProfile = await httpClient.GetUserInfoAsync(userInfo);
            AutenticacionDigital result = new AutenticacionDigital();
            foreach (var claim in userClaims.Claims)
            {
                Type t = result.GetType();
                var p = t.GetProperty(claim.Type);
                if (p != null)
                {
                    p.SetValue(result, claim.Value);
                }
            }

            return Json(result);
        }
    }
}