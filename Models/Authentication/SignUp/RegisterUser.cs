using System.ComponentModel.DataAnnotations;

namespace user.Management.API.Models.SignUp
{
    public class RegisterUser
    {
        [Key]
        public int UserId { get; set; }

        [Required(ErrorMessage = "User Name is required")]
        public string UserName { get; set; }

        [EmailAddress]
        [Required(ErrorMessage = "Email is required")]
        public string Email { get; set; }

        [Required(ErrorMessage = "Password is required")]
        public string Password { get; set; }
    }
}
