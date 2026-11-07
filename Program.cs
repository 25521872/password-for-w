using System;
using System.Collections.Concurrent;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using password_for_w;

// Lưu trữ tài khoản: Username -> UserData
var database = new ConcurrentDictionary<string, UserData>();

// Lưu trữ Token đang hoạt động: Token -> Username
var activeTokens = new ConcurrentDictionary<string, string>();

const int PORT = 5000;
TcpListener server = new TcpListener(IPAddress.Loopback, PORT);
server.Start();

Console.WriteLine("================================");
Console.WriteLine("       PASSWORD TCP SERVER      ");
Console.WriteLine("================================");
Console.WriteLine("Server dang chay va cho Client ket noi...");

while (true)
{
    TcpClient client = await server.AcceptTcpClientAsync();
    _ = XuLyClientAsync(client, database, activeTokens);
}

static async Task XuLyClientAsync(TcpClient client, ConcurrentDictionary<string, UserData> db, ConcurrentDictionary<string, string> tokens)
{
    try
    {
        Console.WriteLine($"[+] Client ket noi: {client.Client.RemoteEndPoint}");
        using (client)
        {
            NetworkStream stream = client.GetStream();
            using StreamReader reader = new StreamReader(stream, Encoding.UTF8, true, 1024, true);
            using StreamWriter writer = new StreamWriter(stream, new UTF8Encoding(false), 1024, true) { AutoFlush = true };

            string? message;
            while ((message = await reader.ReadLineAsync()) != null)
            {
                Console.WriteLine($"[Nhan Request]: {message}");

                using JsonDocument doc = JsonDocument.Parse(message);
                var root = doc.RootElement;
                string action = root.GetProperty("Action").GetString() ?? "";

                string responseJson = "";

                // 1. ĐĂNG KÝ (REGISTER)
                if (action == "Register")
                {
                    string username = root.GetProperty("Username").GetString() ?? "";
                    string password = root.GetProperty("Password").GetString() ?? "";

                    if (db.ContainsKey(username))
                    {
                        responseJson = JsonSerializer.Serialize(new { Status = "ERROR", Message = "Tai khoan da ton tai!" });
                    }
                    else
                    {
                        var (hash, salt) = MatKhau.TaoHashMatKhau(password);
                        db[username] = new UserData { Username = username, PasswordHash = hash, Salt = salt };

                        Console.WriteLine($"[Register OK] User: {username}");
                        responseJson = JsonSerializer.Serialize(new { Status = "OK", Message = "Dang ky thanh cong!" });
                    }
                }
                // 2. ĐĂNG NHẬP (LOGIN)
                else if (action == "Login")
                {
                    string username = root.GetProperty("Username").GetString() ?? "";
                    string password = root.GetProperty("Password").GetString() ?? "";

                    if (!db.TryGetValue(username, out var user))
                    {
                        responseJson = JsonSerializer.Serialize(new { Status = "ERROR", Message = "Tai khoan khong ton tai!" });
                    }
                    else
                    {
                        bool isValid = MatKhau.XacThucMatKhau(password, user.PasswordHash, user.Salt);
                        if (isValid)
                        {
                            string token = Guid.NewGuid().ToString();
                            tokens[token] = username;

                            Console.WriteLine($"[Login OK] User: {username} -> Token: {token}");
                            responseJson = JsonSerializer.Serialize(new { Status = "OK", Message = "Dang nhap thanh cong!", Token = token });
                        }
                        else
                        {
                            Console.WriteLine($"[Login Fail] Sai mat khau: {username}");
                            responseJson = JsonSerializer.Serialize(new { Status = "ERROR", Message = "Sai mat khau!" });
                        }
                    }
                }
                // 3. XÁC THỰC TOKEN (GET USER INFO)
                else if (action == "GetUserInfo")
                {
                    string token = root.GetProperty("Token").GetString() ?? "";

                    if (tokens.TryGetValue(token, out string? username))
                    {
                        Console.WriteLine($"[Token Auth OK] Token hop le cua User: {username}");
                        responseJson = JsonSerializer.Serialize(new { Status = "OK", Message = $"Chao mung {username} den voi he thong!", User = username });
                    }
                    else
                    {
                        Console.WriteLine($"[Token Auth Fail] Token khong hop le hoac da het han!");
                        responseJson = JsonSerializer.Serialize(new { Status = "ERROR", Message = "Token khong hop le hoac phien lam viec da het han!" });
                    }
                }
                // 4. ĐĂNG XUẤT (LOGOUT)
                else if (action == "Logout")
                {
                    string token = root.GetProperty("Token").GetString() ?? "";

                    if (tokens.TryRemove(token, out string? username))
                    {
                        Console.WriteLine($"[Logout OK] User: {username} da huy Token");
                        responseJson = JsonSerializer.Serialize(new { Status = "OK", Message = "Dang xuat thanh cong!" });
                    }
                    else
                    {
                        responseJson = JsonSerializer.Serialize(new { Status = "ERROR", Message = "Token khong ton tai!" });
                    }
                }
                else
                {
                    responseJson = JsonSerializer.Serialize(new { Status = "ERROR", Message = "Hanh dong khong hop le!" });
                }

                await writer.WriteLineAsync(responseJson);
            }
        }
    }
    catch (Exception ex)
    {
        Console.WriteLine($"[-] Loi Client: {ex.Message}");
    }
}

public class UserData
{
    public string Username { get; set; } = "";
    public string PasswordHash { get; set; } = "";
    public string Salt { get; set; } = "";
}