using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Web;

namespace Duo_Web_Two_Factor_Authentication.Helpers
{
    public class DuoWebAuthentication
    {
        private static Encoding _encoding = new UTF8Encoding(false, true);

        public static string DuoWeb_SignRequest(DuoWebRequest Request)
        {
            string duo_sig;
            string app_sig;
            DateTime CurrentDate = DateTime.UtcNow;

            // simple validation checking for the send call - PMT 01/3/2020
            if (Request.USERNAME == "")
            {
                return Error.USER;
            }
            if (Request.USERNAME.Contains("|"))
            {
                return Error.USER;
            }
            if (Request.IKEY.Length != KeyLength.IKEY)
            {
                return Error.IKEY;
            }
            if (Request.SKEY.Length != KeyLength.SKEY)
            {
                return Error.SKEY;
            }
            if (Request.AKEY.Length < KeyLength.AKEY)
            {
                return Error.AKEY;
            }

            try
            {
                // Create Duo Signature and Application Signature
                duo_sig = SignVals(Request.SKEY, Request, DuoProperty.DUO_PREFIX, DuoProperty.DUO_EXPIRE, CurrentDate);
                app_sig = SignVals(Request.AKEY, Request, DuoProperty.APP_PREFIX, DuoProperty.APP_EXPIRE, CurrentDate);
            }
            catch (Exception e)
            {
                //Handle exception if th request fails. Show message to user and show the Exception error
                return Error.UNKNOWN + " (" + e.Message + ") ";
            }

            //Combine both Signatures for the request to the iframe
            return duo_sig + ":" + app_sig;
        }

        public static string DuoWeb_VerifyRequest(DuoWebResponse Request)
        {
            string auth_user = null;
            string app_user = null;

            DateTime CurrentDate = DateTime.UtcNow;

            try
            {
                string[] sigs = Request.RESPONSE.Split(':');
                string auth_sig = sigs[0];
                string app_sig = sigs[1];

                auth_user = ParseVals(Request.SKEY, auth_sig, DuoProperty.AUTH_PREFIX, Request.IKEY, CurrentDate);
                app_user = ParseVals(Request.AKEY, app_sig, DuoProperty.APP_PREFIX, Request.IKEY, CurrentDate);
            }
            catch
            {
                return null;
            }

            if (auth_user != app_user)
            {
                return null;
            }

            return auth_user;
        }

        private static string SignVals(string key, DuoWebRequest Request, string prefix, Int64 expire, DateTime current_time)
        {

            Int64 ts = (Int64)(current_time - new DateTime(1970, 1, 1)).TotalSeconds;
            expire = ts + expire;

            string val = Request.USERNAME + "|" + Request.IKEY + "|" + expire.ToString();
            string cookie = prefix + "|" + Encode64(val);

            string sig = HmacSign(key, cookie);

            return cookie + "|" + sig;
        }

        private static string ParseVals(string key, string val, string prefix, string ikey, DateTime current_time)
        {
            Int64 ts = (int)(current_time - new DateTime(1970, 1, 1)).TotalSeconds;

            string[] parts = val.Split('|');
            if (parts.Length != 3)
            {
                return null;
            }

            string u_prefix = parts[0];
            string u_b64 = parts[1];
            string u_sig = parts[2];

            string sig = HmacSign(key, u_prefix + "|" + u_b64);
            if (HmacSign(key, sig) != HmacSign(key, u_sig))
            {
                return null;
            }

            if (u_prefix != prefix)
            {
                return null;
            }

            string cookie = Decode64(u_b64);
            string[] cookie_parts = cookie.Split('|');
            if (cookie_parts.Length != 3)
            {
                return null;
            }

            string username = cookie_parts[0];
            string u_ikey = cookie_parts[1];
            string expire = cookie_parts[2];

            if (u_ikey != ikey)
            {
                return null;
            }

            long expire_ts = Convert.ToInt64(expire);
            if (ts >= expire_ts)
            {
                return null;
            }

            return username;
        }

        private static string Encode64(string plaintext)
        {
            byte[] plaintext_bytes = _encoding.GetBytes(plaintext);
            return System.Convert.ToBase64String(plaintext_bytes);
        }

        private static string HmacSign(string skey, string data)
        {
            byte[] key_bytes = _encoding.GetBytes(skey);
            using (HMACSHA1 hmac = new HMACSHA1(key_bytes))
            {
                byte[] data_bytes = _encoding.GetBytes(data);
                hmac.ComputeHash(data_bytes);

                string hex = BitConverter.ToString(hmac.Hash);
                return hex.Replace("-", "").ToLower();
            }
        }

        private static string Decode64(string encoded)
        {
            byte[] plaintext_bytes = System.Convert.FromBase64String(encoded);
            return _encoding.GetString(plaintext_bytes);
        }
    }



    public class Error
    {
        public static string USER = "ERROR|The username passed to sign_request() is invalid.";
        public static string IKEY = "ERROR|The Duo integration key passed to sign_request() is invalid.";
        public static string SKEY = "ERROR|The Duo secret key passed to sign_request() is invalid.";
        public static string AKEY = "ERROR|The application secret key passed to sign_request() must be at least 40 characters.";
        public static string UNKNOWN = "ERROR|An unknown error has occurred.";
    }

    public class KeyLength
    {
        public static int IKEY = 20;
        public static int SKEY = 40;
        public static int AKEY = 40;
    }

    public class DuoProperty
    {
        public static string DUO_PREFIX = "TX";
        public static string APP_PREFIX = "APP";
        public static string AUTH_PREFIX = "AUTH";
        public static int DUO_EXPIRE = 300;
        public static int APP_EXPIRE = 3600;
    }

    public class DuoWebRequest
    {
        public string IKEY { get; set; } // Integration Key
        public string SKEY { get; set; } // Duo Secret Key
        public string AKEY { get; set; } // Application Key
        public string USERNAME { get; set; } // Username Key
    }

    public class DuoWebResponse
    {
        public string IKEY { get; set; } // Integration Key
        public string SKEY { get; set; } // Duo Secret Key
        public string AKEY { get; set; } // Application Key
        public string RESPONSE { get; set; } // Username Key
    }
}