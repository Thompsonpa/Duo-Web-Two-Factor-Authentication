using Duo_Web_Two_Factor_Authentication.Helpers;
using Duo_Web_Two_Factor_Authentication.Models;
using System;
using System.Configuration;
using System.Web.Mvc;
using System.Web.Security;

namespace Duo_Web_Two_Factor_Authentication.Controllers
{
    public class HomeController : Controller
    {
        // GET: /Home/Index
        public ActionResult Index()
        {
            return View();
        }

        // GET: /Home/About
        public ActionResult About()
        {
            ViewBag.Message = "Your application description page.";

            return View();
        }

        // GET: /Home/Login
        [AllowAnonymous]
        public ActionResult Login()
        {
            ViewBag.ReturnUrl = "/";
            return View();
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public ActionResult Login(LoginViewModel model)
        {
            Session.Add("loginReturnURL", "/");
            Session.Add("loginUserName", model.UserName);
            if (!ModelState.IsValid) return View(model);

            if (Membership.ValidateUser(model.UserName, model.Password)) // Verify User
            {
                // Duo Authentication
                DuoWebRequest DuoRequest = new DuoWebRequest()  // Create a new Duo Web Request to Send
                {
                    IKEY = ConfigurationManager.AppSettings["ikey"], // Get Integration Key
                    SKEY = ConfigurationManager.AppSettings["skey"], // Get DUO Secret Key
                    AKEY = ConfigurationManager.AppSettings["akey"], // Generate Unique Application Secret Key for DUO
                    USERNAME = model.UserName
                };

                string signRequest = DuoWebAuthentication.DuoWeb_SignRequest(DuoRequest); // Create signed Request for user to DUO

                Session.Add("SignRequest", signRequest);
                return this.RedirectToAction("DuoAuthentication"); // Send user to Authentication Page For Duo's jQuery code
            }
            return View(model); // User is invlid just show model
        }

        // GET: /Home/DuoAuthentication
        [AllowAnonymous]
        public ActionResult DuoAuthentication()
        {
            return View("");
        }

        [HttpPost]
        [AllowAnonymous]
        public ActionResult DuoAuthenticationVerify(string sig_response)
        {
            // Get Duo Request that was passed
            var signRequest = sig_response; // Get Unique Application Secret Key that was generated for user for this login

            DuoWebResponse DuoResponse = new DuoWebResponse()  // Create Duo Response to send to the verify Request
            {
                IKEY = ConfigurationManager.AppSettings["DUOIKEY"],
                SKEY = ConfigurationManager.AppSettings["DUOSKEY"],
                AKEY = ConfigurationManager.AppSettings["DUOAKEY"],
                RESPONSE = signRequest
            };

            var authenticated_username = DuoWebAuthentication.DuoWeb_VerifyRequest(DuoResponse);
            if (String.IsNullOrEmpty(authenticated_username))
            {
                return Redirect("/Home/Login"); // User is not verified send back to the login page
            }
            else
            {
                //If verified through Duo assign Cookie information
                string theLoginUserName = Session["loginUserName"].ToString();
                string returnUrl = Session["loginReturnURL"].ToString();  //Default to the root site
                Session.Remove("loginUserName"); // Remove Seesion no longer needed                
                Session.Remove("loginUserName"); // Remove Seesion no longer needed
                var authCookie = FormsAuthentication.GetAuthCookie(theLoginUserName, true); // Get Login Authorization           
                Security.updateCookieExpiration(Request, Response, authCookie); // Update Cookie            
                
                return Redirect(returnUrl); // Redirect user to return login. Page after user logs in successfully
            }
        }

        // GET: /Home/Contact
        public ActionResult Contact()
        {
            ViewBag.Message = "Your contact page.";

            return View();
        }
    }
}