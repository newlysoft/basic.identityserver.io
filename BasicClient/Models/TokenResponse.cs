using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace BasicClient.Models
{
    public class TokenResponse
    {
        public string IdentityToken { get; set; }
        public string AccessToken { get; set; }

        public bool IsError { get; set; }
        public string Error { get; set; }
    }
}