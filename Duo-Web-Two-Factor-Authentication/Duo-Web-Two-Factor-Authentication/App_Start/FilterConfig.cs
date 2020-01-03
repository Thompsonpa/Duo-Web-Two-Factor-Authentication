using System.Web;
using System.Web.Mvc;

namespace Duo_Web_Two_Factor_Authentication
{
    public class FilterConfig
    {
        public static void RegisterGlobalFilters(GlobalFilterCollection filters)
        {
            filters.Add(new HandleErrorAttribute());
        }
    }
}
