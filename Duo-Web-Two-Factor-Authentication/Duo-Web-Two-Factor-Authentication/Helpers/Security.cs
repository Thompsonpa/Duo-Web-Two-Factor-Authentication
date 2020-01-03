using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace Duo_Web_Two_Factor_Authentication.Helpers
{
    public class Security
    {
        public static void updateCookieExpiration(HttpRequestBase request, HttpResponseBase response, HttpCookie cookie)
        {
            // Write Cookie Update/get Code 
            response.Cookies.Add(cookie);
        }


    }
}