using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace SampleAuthWebApp.Controllers
{
    [Route("api/[controller]/[action]")]
    [ApiController]
    public class TestController : ControllerBase
    {
        public TestController()
        {
        }

        [HttpPost]
        public async Task<ActionResult<TestDataDto>> GetTestData([FromBody] TestDataRequest testDataRequest)
        {
            var testDataDto = new TestDataDto() { message = "received: " + testDataRequest.message };
            return Ok(testDataDto);
        }

        [HttpPost]
        [Authorize(Roles = "User")]
        public async Task<ActionResult<TestDataDto>> GetUserTestData([FromBody] TestDataRequest testDataRequest)
        {
            var testDataDto = new TestDataDto() { message = "received: " + testDataRequest.message };
            return Ok(testDataDto);
        }

        [HttpPost]
        [Authorize(Roles = "Server")]
        public async Task<ActionResult<TestDataDto>> GetServerTestData([FromBody] TestDataRequest testDataRequest)
        {
            var testDataDto = new TestDataDto() { message = "received: " + testDataRequest.message };
            return Ok(testDataDto);
        }

        [HttpGet]
        public async Task<ActionResult<string>> GetUserToken()
        {
            var token = Program.GetUserToken();
            return Ok(token);
        }

        [HttpGet]
        public async Task<ActionResult<string>> GetServerToken()
        {
            var token = Program.GetServerToken();
            return Ok(token);
        }

    }
}
