using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace SampleJwtWebApp.Controllers
{
    [Route("api/[controller]/[action]")]
    [ApiController]
    [Authorize]
    public class TestController : ControllerBase
    {

        public TestController()
        {

        }

        [HttpGet]
        public async Task<ActionResult<TestDataDto>> GetTestData()
        {
            var name = HttpContext.User.Identity.Name;
            var isAuthenticated = HttpContext.User.Identity.IsAuthenticated;
            var isUser = HttpContext.User.IsInRole("User");
            var isServer = HttpContext.User.IsInRole("Server");
            var testDataDto = new TestDataDto()
            {
                message = $"name:{name}, isAuthenticated:{isAuthenticated}, isUser:{isUser}, isServer:{isServer}"
            };
            return Ok(testDataDto);
        }
    }
}