using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using user.Management.API.Models;
using user.Management.API.Models.Authentication.Login;
using user.Management.API.Models.SignUp;
using User.Management.Service.Models;
using User.Management.Service.Services;

namespace user.Management.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _SignInManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IEmailService _emailService;
        private readonly IConfiguration _configuration;

        public AuthenticationController(UserManager<IdentityUser> userManager,
            RoleManager<IdentityRole> roleManager, IEmailService emailService, SignInManager<IdentityUser> SignInManager,IConfiguration configuration)
        {
            _userManager = userManager;
            _SignInManager = SignInManager;
            _roleManager = roleManager;
            _emailService = emailService;
            _configuration = configuration;
        }
        [HttpPost]
        public async Task<ActionResult> Register([FromBody] RegisterUser registerUser, string role)
        {
            // checked user exist
            var userExist = await _userManager.FindByEmailAsync(registerUser.Email);
            if (userExist != null)
            {
                return StatusCode(StatusCodes.Status403Forbidden,
                    new Response { Status = "Error", Message = "User already exists!" });
            }

            // Add the user in the database
            IdentityUser user = new()
            {
                Email = registerUser.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = registerUser.UserName,
                TwoFactorEnabled = true

            };
            if (await _roleManager.RoleExistsAsync(role))
            {


                var result = await _userManager.CreateAsync(user, registerUser.Password);
                if (!result.Succeeded)
                {
                    return StatusCode(StatusCodes.Status500InternalServerError,
                     new Response { Status = "Error", Message = "User Failed to Create" });
                }
                //Add role to the user.....



                await _userManager.AddToRoleAsync(user, role);
                //Add Token to verify the email....
                var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                var confirmationLink = Url.Action(nameof(ConfirmEmail), "Authentication", new { token, email = user.Email }, Request.Scheme);

               
                var message = new Message(new string[] { user.Email! }, "Confirmation email link", confirmationLink!);
                _emailService.SendEmail(message);


                return StatusCode(StatusCodes.Status200OK,
                 new Response { Status = "Success", Message = $"User Created & Email sent to {user.Email} Successfully" });
            }
            else
            {

                return StatusCode(StatusCodes.Status500InternalServerError,
                 new Response { Status = "Error", Message = "This Role Doesnot Exist." });
            }
        }
       

        [HttpGet("ConfirmEmail")]
        public async Task<IActionResult> ConfirmEmail(string email,string token)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user != null)
            {
                var result = await _userManager.ConfirmEmailAsync(user ,token);
                if (result.Succeeded)
                {
                    return StatusCode(StatusCodes.Status200OK,
                        new Response { Status = "Success", Message = "Email Verified Successfully" });
                }

            }
            return StatusCode(StatusCodes.Status500InternalServerError,
                        new Response { Status = "Error", Message = "This User Doesnot exist!" });






        }
        [HttpPost]  
        [Route("login")]
        public async Task<ActionResult> Login([FromBody] LoginModel loginModel)

        {
            //checking the user....
            var user = await _userManager.FindByNameAsync(loginModel.Username);
            if (user.TwoFactorEnabled)
            {
                await _SignInManager.SignOutAsync();
                await _SignInManager.PasswordSignInAsync(user, loginModel.Password, false, true);
                var token = await _userManager.GenerateTwoFactorTokenAsync(user, "Email");
                var message = new Message(new string[] { user.Email!}, "OTP Confirmation", token);
                _emailService.SendEmail(message);
                return StatusCode(StatusCodes.Status200OK,
                     new Response { Status = "Success", Message = $"We have sent an OTP to your Email{user.Email}" });
            }
            if (user != null && await _userManager.CheckPasswordAsync(user, loginModel.Password))
            {
                var authClaims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name,user.UserName),
                    new Claim(JwtRegisteredClaimNames.Jti,Guid.NewGuid().ToString()),
                };
                var UserRoles = await _userManager.GetRolesAsync(user);
                foreach(var role in UserRoles)
                {
                    authClaims.Add(new Claim(ClaimTypes.Role, role));
                }
               

                var jwtToken = GetToken(authClaims);

                return Ok(new
                {
                    token = new JwtSecurityTokenHandler().WriteToken(jwtToken),
                    expiration =jwtToken.ValidTo
                });

                //returning the token...
            }
            return Unauthorized();
            









        }
        [HttpPost]
        [Route("login-2FA")]
        public async Task<ActionResult> LoginWithOTP(string code, string username)
        {


            var user = await _userManager.FindByEmailAsync(username);
            var signIn = await _SignInManager.TwoFactorSignInAsync("Email", code, false, false);
            if (signIn.Succeeded)
            {
                if (user != null)
                {
                    var authClaims = new List<Claim>

                    {
                     new Claim(ClaimTypes.Name, user.UserName),
                     new Claim(JwtRegisteredClaimNames.Jti,Guid.NewGuid().ToString()),
                    };
                    var UserRoles = await _userManager.GetRolesAsync(user);
                    foreach (var role in UserRoles)
                    {
                        authClaims.Add(new Claim(ClaimTypes.Role, role));
                    }


                    var jwtToken = GetToken(authClaims);

                    return Ok(new
                    {
                        token = new JwtSecurityTokenHandler().WriteToken(jwtToken),
                        expiration = jwtToken.ValidTo
                    });
                }
            }
            else if (signIn.IsLockedOut)
            {
                // Handle the scenario where the user is locked out
                return StatusCode(StatusCodes.Status403Forbidden,
                    new Response { Status = "Error", Message = "Account is locked out. Please try again later." });
            }
            else
            {
                // Handle the scenario where two-factor authentication failed
                return StatusCode(StatusCodes.Status401Unauthorized,
                    new Response { Status = "Error", Message = "Invalid two-factor authentication code." });
            }
            return StatusCode(StatusCodes.Status404NotFound,
                new Response { Status = "Error", Message = "Invalid Token" });
        }
                   

                          
           
        

        private JwtSecurityToken GetToken(List<Claim> authClaims)
        {
            var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));
            var token = new JwtSecurityToken(
                issuer: _configuration["JWT:ValidIssuer"],
                audience: _configuration["JWT:ValidAudience"],
                expires: DateTime.Now.AddHours(1),
                claims: authClaims,
                signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
                 );
            return token;
        }
        
    }
}