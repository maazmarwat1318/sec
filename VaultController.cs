[ApiController]
[Route("api/[controller]")]
public class VaultController : ControllerBase
{
    private readonly IEncryptionService _encryption;
    private readonly MyDbContext _context;

    public VaultController(IEncryptionService encryption, MyDbContext context)
    {
        _encryption = encryption;
        _context = context;
    }

    [HttpPost("add-secret")]
    [Authorize] // Requires authentication
    public async Task<IActionResult> AddSecret([FromBody] string rawSecret)
    {
        // 1. Encrypt the data using our service
        string encryptedSecret = _encryption.Encrypt(rawSecret);

        // 2. Save the encrypted string to the DB
        var entry = new VaultEntry { Content = encryptedSecret, UserId = User.Identity.Name };
        _context.VaultEntries.Add(entry);
        await _context.SaveChangesAsync();

        return Ok("Secret stored securely.");
    }

    [HttpGet("view-secret/{id}")]
    public async Task<IActionResult> GetSecret(int id)
    {
        var entry = await _context.VaultEntries.FindAsync(id);
        if (entry == null) return NotFound();

        // 3. Decrypt on the fly for the authorized user
        string decryptedSecret = _encryption.Decrypt(entry.Content);
        return Ok(new { Secret = decryptedSecret });
    }
}